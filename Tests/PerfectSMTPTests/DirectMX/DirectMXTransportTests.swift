//
//  DirectMXTransportTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 3 / this task's required coverage list: MX preference-order
//  host fallback, null-MX hard-fail, no-MX A/AAAA implicit-MX fallback,
//  multi-recipient/multi-domain independence, circuit-breaker integration,
//  and `.ambiguous` never being queued for retry. Uses the `MXResolving`
//  seam (`FakeMXResolver`) plus `DirectMXTransport`'s test-only injectable-
//  dialer `init` (mirroring `SMTPConnectionPool`'s own test seam) so every
//  test here is fully deterministic, in-memory, and touches neither a real
//  socket nor real DNS.
//

import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct DirectMXTransportTests {
    private func envelope(mailFrom: String = "from@sender.example", recipients: [String]) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address(mailFrom), recipients: recipients)
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    // MARK: - MX preference-order host fallback

    @Test func firstPreferenceHostFailsSecondPreferenceHostSucceeds() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "fallback.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "mx1.fallback.example"),
                DNSResolver.MXRecord(preference: 20, exchange: "mx2.fallback.example"),
            ]
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "mx1.fallback.example": throw SimulatedConnectFailure(label: "mx1 down")
            case "mx2.fallback.example": return try await succeedingHost(key)
            default: throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["rcpt@fallback.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the fallback host, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - Null-MX hard-fail

    @Test func nullMXHardFailsWithNoRetryAndNoAddressFallback() async throws {
        let resolveAddressesCalls = CallCountBox()
        let resolver = FakeMXResolver(
            mxErrors: ["nullmx.example": .nullMX],
            onResolveAddresses: { _ in Task { await resolveAddressesCalls.increment() } }
        )
        // Any dial attempt at all is a bug for this test -- null-MX must
        // hard-fail before ever reaching the connection pool.
        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: failingDialer())

        let results = try await transport.send(try envelope(recipients: ["victim@nullmx.example"]), message())

        #expect(results.count == 1)
        guard case .permanentlyFailed(let reply) = results[0].outcome else {
            Issue.record("expected .permanentlyFailed, got \(results[0].outcome)")
            return
        }
        #expect(reply.code == 556)

        // No retry queued -- permanent failures never enter the retry queue.
        let pending = await transport.pendingRetryEntries()
        #expect(pending.isEmpty)

        // The RFC 5321 §5.1 implicit-MX fallback must never be attempted
        // for a null-MX domain -- that's the entire point of RFC 7505.
        try await Task.sleep(nanoseconds: UInt64(10) * 1_000_000)
        #expect(await resolveAddressesCalls.count == 0)
    }

    // MARK: - No-MX-records -> A/AAAA implicit-MX fallback

    @Test func noMXRecordsFallsBackToTheDomainsOwnAddressRecord() async throws {
        // `nomx.example` is deliberately absent from `mxRecords` -- `FakeMXResolver`
        // throws `.noRecordsFound` for any domain it doesn't recognize,
        // exactly like a real NODATA response.
        let resolver = FakeMXResolver()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            // The only way this dialer is ever invoked with `key.host ==
            // "nomx.example"` (the domain itself, not an MX exchange name)
            // is if `deliverToDomain` correctly fell back to treating the
            // domain as its own implicit MX.
            guard key.host == "nomx.example" else { throw SimulatedConnectFailure(label: "unexpected host \(key.host)") }
            return try await scriptedDialer()(key)
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["rcpt@nomx.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the domain's own implicit MX, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - Multi-recipient, multi-domain independence

    @Test func oneDomainsFailureDoesNotAffectAnotherDomainsDelivery() async throws {
        let resolver = FakeMXResolver(
            mxRecords: ["good.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.good.example")]],
            mxErrors: ["bad.example": .nullMX]
        )
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            guard key.host == "mx.good.example" else { throw SimulatedConnectFailure(label: "unexpected host \(key.host)") }
            return try await scriptedDialer()(key)
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(
            try envelope(recipients: ["good@good.example", "bad@bad.example"]), message()
        )

        #expect(results.count == 2)
        let good = results.first { $0.recipient == "good@good.example" }
        let bad = results.first { $0.recipient == "bad@bad.example" }

        guard let good, case .delivered = good.outcome else {
            Issue.record("expected good@good.example delivered, got \(String(describing: good?.outcome))")
            return
        }
        guard let bad, case .permanentlyFailed = bad.outcome else {
            Issue.record("expected bad@bad.example permanently failed, got \(String(describing: bad?.outcome))")
            return
        }
    }

    // MARK: - Circuit breaker integration

    @Test func repeatedHostFailuresTripTheBreakerAndFallbackRoutesAroundIt() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "breaker.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "flaky.breaker.example"),
                DNSResolver.MXRecord(preference: 20, exchange: "reliable.breaker.example"),
            ]
        ])
        let flakyDialAttempts = CallCountBox()
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "flaky.breaker.example":
                await flakyDialAttempts.increment()
                throw SimulatedConnectFailure(label: "flaky host down")
            case "reliable.breaker.example":
                return try await succeedingHost(key)
            default:
                throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let threshold = 2
        // `.fixed(.none)` -- this test asserts an *exact* dial-attempt
        // count against the flaky host, which the opportunistic default
        // (two candidate keys, `.startTLS` then `.none`, each with its own
        // independently-tracked circuit-breaker state) would double,
        // decoupling the assertion from what this test actually cares
        // about (breaker-driven host fallback, not TLS-mode selection).
        let config = DirectMXConfig(
            tlsPolicy: .fixed(.none),
            pool: .init(maxPerHost: 4, maxTotal: 100, circuitBreakerThreshold: threshold, circuitBreakerResetTimeout: 30)
        )
        let transport = DirectMXTransport(resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(), dialer: dialer)

        // Every call still succeeds end-to-end (via the fallback host),
        // regardless of the flaky host's breaker state -- fallback and
        // breaker tripping are independent, composing correctly together.
        for _ in 0..<(threshold + 2) {
            let results = try await transport.send(try envelope(recipients: ["rcpt@breaker.example"]), message())
            guard case .delivered = results[0].outcome else {
                Issue.record("expected .delivered via the fallback host even while the flaky host's breaker is tripping")
                return
            }
        }

        // Once the breaker opens (after `threshold` consecutive dial
        // failures), `SMTPConnectionPool.checkout` short-circuits with
        // `.circuitOpen` *before* ever calling the dialer again -- so the
        // flaky host's dial-attempt count must stop climbing at exactly
        // `threshold`, proving the breaker tripped and
        // `deliverToDomain`'s own host-fallback loop is routing around it
        // (not just coincidentally retrying a host that keeps failing).
        #expect(await flakyDialAttempts.count == threshold)
    }

    @Test func allHostsBreakerTrippedSurfacesCircuitOpenAsFailed() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "alldown.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.alldown.example")]
        ])
        let threshold = 2
        let config = DirectMXConfig(pool: .init(circuitBreakerThreshold: threshold, circuitBreakerResetTimeout: 30))
        let transport = DirectMXTransport(
            resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(),
            dialer: failingDialer(label: "always down")
        )

        var lastResults: [DeliveryResult] = []
        for _ in 0..<(threshold + 1) {
            lastResults = try await transport.send(try envelope(recipients: ["rcpt@alldown.example"]), message())
        }

        #expect(lastResults.count == 1)
        // Release review: an open breaker is temporary -- queued for retry.
        guard case .queuedForRetry(_, _, let last) = lastResults[0].outcome, last.code == 451 else {
            Issue.record("expected a temporary failure once the sole host's breaker is open, got \(lastResults[0].outcome)")
            return
        }
        #expect(last.lines.joined().contains("circuitOpen"), "expected the failure to name SMTPError.circuitOpen, got \(last.lines)")
    }

    // MARK: - `.ambiguous` is never queued for retry

    @Test func ambiguousOutcomeIsNeverQueuedForRetry() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "ambiguous.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.ambiguous.example")]
        ])
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { _ in
            let (connection, channel) = try await ConnectionHarness.make()
            Task {
                guard let ehlo = try? await expectClientLine(channel), ehlo.hasPrefix("EHLO") else { return }
                try? await serverSend(channel, "250 mx.ambiguous.example Hello")
                guard let mail = try? await expectClientLine(channel), mail.hasPrefix("MAIL FROM") else { return }
                try? await serverSend(channel, "250 2.1.0 OK")
                guard let rcpt = try? await expectClientLine(channel), rcpt.hasPrefix("RCPT TO") else { return }
                try? await serverSend(channel, "250 2.1.5 OK")
                guard let data = try? await expectClientLine(channel), data == "DATA" else { return }
                try? await serverSend(channel, "354 Go ahead")
                _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                // Simulate a disconnect exactly in the point-of-no-return
                // window (after the DATA payload is sent, before the final
                // reply arrives) instead of ever sending a final reply --
                // this is what `SMTPConnection.sendBodyAndFinalize`
                // classifies as `.ambiguous`.
                channel.close(promise: nil)
            }
            try await connection.negotiateCapabilities()
            return connection
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["victim@ambiguous.example"]), message())

        #expect(results.count == 1)
        guard case .ambiguous = results[0].outcome else {
            Issue.record("expected .ambiguous, got \(results[0].outcome)")
            return
        }

        // `send(_:_:)` awaits its own retry-enqueue step before returning,
        // so this is safe to assert immediately -- `.ambiguous` must never
        // reach the retry queue at all.
        let pending = await transport.pendingRetryEntries()
        #expect(pending.isEmpty)
    }

    // MARK: - FIX #1 (milestone architecture + SMTP-protocol reviews): a
    // mid-DATA disconnect or a `421` must feed the circuit breaker's
    // failure count (never `recordSuccess`) and must not be returned to
    // the idle pool -- previously `attemptOnHost`'s catch-and-return
    // handling of these outcomes made `pool.withConnection`'s body return
    // normally regardless, so `release` always saw `healthy: true`.

    /// Before the fix: an `.ambiguous` mid-DATA disconnect made
    /// `release(healthy: true)` call `recordSuccess`, so the breaker's
    /// consecutive-failure count never moved off zero no matter how many
    /// ambiguous deliveries a host produced. This test uses
    /// `circuitBreakerThreshold: 1` so a *single* ambiguous delivery must
    /// be sufficient to open the breaker if (and only if) `release`
    /// correctly classified it as unhealthy and called `recordFailure`
    /// rather than `recordSuccess` (note the dial itself still succeeds --
    /// `checkout`'s own post-dial `recordSuccess` already resets the
    /// count to 0 at that point, same as always; it's specifically the
    /// *post-transaction* `release` call this test isolates).
    @Test func ambiguousMidDataDisconnectFeedsBreakerFailureCountNotSuccess() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "goesambiguous.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.goesambiguous.example")]
        ])
        let dialAttempts = CallCountBox()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { _ in
            await dialAttempts.increment()
            let attemptNumber = await dialAttempts.count
            guard attemptNumber == 1 else {
                throw SimulatedConnectFailure(label: "unexpected second dial -- breaker should already be open")
            }
            let (connection, channel) = try await ConnectionHarness.make()
            Task {
                guard let ehlo = try? await expectClientLine(channel), ehlo.hasPrefix("EHLO") else { return }
                try? await serverSend(channel, "250 mx.goesambiguous.example Hello")
                guard let mail = try? await expectClientLine(channel), mail.hasPrefix("MAIL FROM") else { return }
                try? await serverSend(channel, "250 2.1.0 OK")
                guard let rcpt = try? await expectClientLine(channel), rcpt.hasPrefix("RCPT TO") else { return }
                try? await serverSend(channel, "250 2.1.5 OK")
                guard let data = try? await expectClientLine(channel), data == "DATA" else { return }
                try? await serverSend(channel, "354 Go ahead")
                _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                // Disconnect in the point-of-no-return window instead of
                // ever sending a final reply -- `SMTPConnection
                // .sendBodyAndFinalize` classifies this as `.ambiguous`.
                channel.close(promise: nil)
            }
            try await connection.negotiateCapabilities()
            return connection
        }

        // `.fixed(.none)` -- see the identical note on
        // `repeatedHostFailuresTripTheBreakerAndFallbackRoutesAroundIt`:
        // this test's `dialAttempts` guard hard-fails on any dial beyond
        // the first, which the opportunistic default's second (`.none`)
        // candidate key would trigger after the first (`.startTLS`) key's
        // breaker trips, for reasons unrelated to what this test covers.
        let config = DirectMXConfig(tlsPolicy: .fixed(.none), pool: .init(circuitBreakerThreshold: 1, circuitBreakerResetTimeout: 30))
        let transport = DirectMXTransport(resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(), dialer: dialer)

        let r1 = try await transport.send(try envelope(recipients: ["a@goesambiguous.example"]), message())
        guard case .ambiguous = r1[0].outcome else {
            Issue.record("expected the first attempt to be .ambiguous, got \(r1[0].outcome)")
            return
        }

        // A second send to the same domain must see the breaker already
        // open -- proving the ambiguous outcome fed `recordFailure`
        // (not `recordSuccess`) during `release`.
        let r2 = try await transport.send(try envelope(recipients: ["b@goesambiguous.example"]), message())
        guard case .queuedForRetry(_, _, let last) = r2[0].outcome, last.lines.joined().contains("circuitOpen") else {
            Issue.record("expected the second attempt to fail with SMTPError.circuitOpen (proving the ambiguous outcome fed the breaker), got \(r2[0].outcome)")
            return
        }
        #expect(await dialAttempts.count == 1)
    }

    /// Before the fix: a `421` final reply (mid-transaction, after DATA)
    /// left the underlying `NIOAsyncTestingChannel` open (the server just
    /// sends the reply, it doesn't close the socket -- exactly like a real
    /// peer announcing "closing the transmission channel" without having
    /// actually torn the TCP connection down yet), so `release`'s old
    /// unconditional `healthy: true` path would find `channel.isActive ==
    /// true` and both (a) call `recordSuccess`, never feeding the breaker,
    /// and (b) hand the connection back to the idle pool for reuse. This
    /// test uses `circuitBreakerThreshold: 1` so a single 421 must be
    /// sufficient to open the breaker if (and only if) it was correctly
    /// classified as unhealthy.
    @Test func serviceUnavailable421FeedsBreakerAndConnectionIsNotReturnedToIdlePool() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "goes421.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.goes421.example")]
        ])
        let dialAttempts = CallCountBox()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { _ in
            await dialAttempts.increment()
            let attemptNumber = await dialAttempts.count
            guard attemptNumber == 1 else {
                throw SimulatedConnectFailure(label: "unexpected second dial -- breaker should already be open, or the 421'd connection was wrongly reused from idle")
            }
            // A short `replyTimeout` (real-time, not tied to
            // `NIOAsyncTestingEventLoop`'s virtual clock -- matching
            // `SMTPConnectionStateMachineTests`' FIX #4 timeout tests):
            // bounds how long a *regression* of this fix (the 421'd
            // connection wrongly handed back to idle, then reused for a
            // second MAIL FROM no scripted task is listening for) would
            // make this test hang, rather than letting it stall for the
            // full 300s production default.
            let (connection, channel) = try await ConnectionHarness.make(replyTimeout: 2)
            Task {
                guard let ehlo = try? await expectClientLine(channel), ehlo.hasPrefix("EHLO") else { return }
                try? await serverSend(channel, "250 mx.goes421.example Hello")
                guard let mail = try? await expectClientLine(channel), mail.hasPrefix("MAIL FROM") else { return }
                try? await serverSend(channel, "250 2.1.0 OK")
                guard let rcpt = try? await expectClientLine(channel), rcpt.hasPrefix("RCPT TO") else { return }
                try? await serverSend(channel, "250 2.1.5 OK")
                guard let data = try? await expectClientLine(channel), data == "DATA" else { return }
                try? await serverSend(channel, "354 Go ahead")
                _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                // The peer's own "closing the transmission channel"
                // announcement -- note the underlying socket is
                // deliberately left open here (not `channel.close()`),
                // matching a real 421 that hasn't yet been followed by an
                // actual TCP teardown.
                try? await serverSend(channel, "421 4.3.2 Service unavailable, closing channel")
            }
            try await connection.negotiateCapabilities()
            return connection
        }

        // `.fixed(.none)` -- same rationale as the other breaker-count
        // tests above: this test's `dialAttempts` guard is exact-count
        // sensitive, which the opportunistic default's second candidate
        // key would perturb for reasons unrelated to what this test
        // covers (421 feeding the breaker and not idling the connection).
        let config = DirectMXConfig(tlsPolicy: .fixed(.none), pool: .init(circuitBreakerThreshold: 1, circuitBreakerResetTimeout: 30))
        let transport = DirectMXTransport(resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(), dialer: dialer)

        let r1 = try await transport.send(try envelope(recipients: ["a@goes421.example"]), message())
        guard case .queuedForRetry(_, _, let last) = r1[0].outcome, last.code == 421 else {
            Issue.record("expected the first attempt to be .queuedForRetry carrying the 421 reply, got \(r1[0].outcome)")
            return
        }

        // A second send to the same domain must see the breaker already
        // open (proving the 421 both fed `recordFailure` and the
        // connection was closed rather than idled) -- if the connection
        // had instead been idled, this checkout would try to reuse it
        // (dialAttempts staying at 1 for a *different* reason: no second
        // dial because of idle reuse, not because of an open breaker) and
        // hang writing a second MAIL FROM against a scripted server task
        // that already exited after replying once.
        let r2 = try await transport.send(try envelope(recipients: ["b@goes421.example"]), message())
        guard case .queuedForRetry(_, _, let last) = r2[0].outcome, last.lines.joined().contains("circuitOpen") else {
            Issue.record("expected the second attempt to fail with SMTPError.circuitOpen, got \(r2[0].outcome)")
            return
        }
        #expect(await dialAttempts.count == 1)
    }

    // MARK: - FIX #2 (milestone security review): SSRF-class address
    // filtering. Uses the real public `init(resolver:config:group:...)`
    // (not the test-only injectable-dialer seam) specifically because the
    // filter lives inside `makeDialer` itself -- the production dialer the
    // test-only `dialer:` init bypasses entirely.

    /// A fake resolver handing back a loopback address for a domain's MX
    /// exchange must never reach a real connection attempt -- the address
    /// is filtered out before `makeDialer`'s dial loop even starts (an
    /// empty post-filter address list is checked before the loop, so
    /// `SMTPBootstrap.connect` is never called at all here), and delivery
    /// fails with the new, distinct `DirectMXError
    /// .allResolvedAddressesFilteredAsPrivate` -- not some generic/
    /// ambiguous connection failure.
    @Test func allAddressesFilteredAsPrivateFailsWithADistinctErrorNotAConnectionAttempt() async throws {
        let resolver = FakeMXResolver(
            mxRecords: ["ssrf.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.ssrf.example")]],
            addresses: ["mx.ssrf.example": [.v4([127, 0, 0, 1]), .v4([10, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop())

        let results = try await transport.send(try envelope(recipients: ["victim@ssrf.example"]), message())

        #expect(results.count == 1)
        guard case .failed(let error) = results[0].outcome else {
            Issue.record("expected .failed once every resolved address is filtered as private, got \(results[0].outcome)")
            return
        }
        guard let directMXError = error as? DirectMXError,
              case .allResolvedAddressesFilteredAsPrivate(let host) = directMXError
        else {
            Issue.record("expected DirectMXError.allResolvedAddressesFilteredAsPrivate, got \(error)")
            return
        }
        #expect(host == "mx.ssrf.example")
    }

    // MARK: - Smaller fix (both reviews): DNS-infrastructure resolve
    // failures (`.timeout`/`.serverFailure`/`.noNameserversConfigured`)
    // are plausibly transient and must be queued for retry, not
    // immediately, permanently `.failed` -- unlike `.nullMX`/`.cnameLoop`,
    // which stay exactly as they were (domain-authoritative/structural,
    // correctly permanent).

    @Test func dnsTimeoutGetsQueuedForRetryRatherThanImmediatelyFailing() async throws {
        let resolver = FakeMXResolver(mxErrors: ["flaky-dns.example": .timeout])
        // Any dial attempt at all is a bug for this test -- a DNS timeout
        // must never reach the connection pool.
        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: failingDialer())

        let results = try await transport.send(try envelope(recipients: ["victim@flaky-dns.example"]), message())

        #expect(results.count == 1)
        guard case .queuedForRetry(_, _, let last) = results[0].outcome else {
            Issue.record("expected .queuedForRetry, got \(results[0].outcome)")
            return
        }
        // Not a permanent-failure reply code -- the synthesized reply this
        // classification attaches is 4yz (transient), not 5yz.
        #expect(last.replyClass == .transientNegative)

        // `send(_:_:)` awaits its own retry-enqueue step before returning,
        // so this is safe to assert immediately.
        let pending = await transport.pendingRetryEntries()
        #expect(pending.count == 1)
        #expect(pending.first?.recipients == ["victim@flaky-dns.example"])

        await transport.shutdown()
    }

    /// `.nullMX` and `.cnameLoop` must be entirely unaffected by the DNS-
    /// infrastructure-retry fix above -- still immediately terminal, never
    /// queued. `.nullMX` is already covered end-to-end by
    /// `nullMXHardFailsWithNoRetryAndNoAddressFallback`; this covers
    /// `.cnameLoop` specifically (a structural/domain problem, not a
    /// resolver hiccup).
    @Test func cnameLoopStaysImmediatelyFailedNotQueuedForRetry() async throws {
        let resolver = FakeMXResolver(mxErrors: ["cnameloop.example": .cnameLoop])
        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: failingDialer())

        let results = try await transport.send(try envelope(recipients: ["victim@cnameloop.example"]), message())

        #expect(results.count == 1)
        guard case .failed(let error) = results[0].outcome else {
            Issue.record("expected .failed, got \(results[0].outcome)")
            return
        }
        guard let resolveError = error as? DNSResolver.ResolveError, case .cnameLoop = resolveError else {
            Issue.record("expected the .failed outcome to wrap DNSResolver.ResolveError.cnameLoop, got \(error)")
            return
        }

        let pending = await transport.pendingRetryEntries()
        #expect(pending.isEmpty)

        await transport.shutdown()
    }
}

/// A trivial actor counter -- used by these tests to assert on how many
/// times a dialer/resolver method was actually invoked.
actor CallCountBox {
    private(set) var count = 0
    func increment() { count += 1 }
}

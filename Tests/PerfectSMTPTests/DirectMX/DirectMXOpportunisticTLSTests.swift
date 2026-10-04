//
//  DirectMXOpportunisticTLSTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4, point 4: the new opportunistic-TLS-by-default behavior,
//  end-to-end against real `NIOPosix` sockets -- mirroring
//  `STARTTLSRealSocketTests.swift`/`DirectMXRealSocketTests.swift`'s
//  established pattern (a minimal in-process fake SMTP server driven by
//  `ServerBootstrap`, not `EmbeddedChannel`), because this behavior is
//  specifically about what `DirectMXTransport`'s *production* dialer
//  (`makeDialer`, via `SMTPBootstrap.connect`) actually does against a real
//  socket -- the same reason `DirectMXRealSocketTests` exists rather than
//  relying solely on the test-only injectable-dialer seam.
//
//  Three scenarios, matching this task's required coverage exactly:
//  (1) a server advertising STARTTLS gets a TLS attempt by default (no MTA-
//      STS policy needed -- `DirectMXConfig()`'s own new default,
//      `tlsPolicy: .opportunistic`, is exercised with no override at all);
//  (2) a server not advertising STARTTLS falls back to plaintext rather
//      than failing the whole delivery;
//  (3) **the security-critical one:** a genuine STARTTLS-injection
//      detection during the opportunistic attempt still hard-fails --
//      it must NOT fall back to plaintext, which would be exactly the
//      downgrade-attack outcome the STARTTLS buffer-discipline design
//      (plan §4.3) exists to prevent.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DirectMXOpportunisticTLSTests {
    private func envelope(recipients: [String]) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: recipients)
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    // MARK: - (1) STARTTLS advertised -> gets a real attempt by default

    @Test func aServerAdvertisingSTARTTLSGetsATLSAttemptByDefaultWithNoMTASTSPolicyNeeded() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sawSTARTTLS = SeenFlag()
        let server = try await AdvertisingButNeverUpgradingFakeSMTPServer.start(group: group, onSTARTTLS: { await sawSTARTTLS.markSeen() })

        let resolver = FakeMXResolver(
            mxRecords: ["advertises.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.advertises.example")]],
            addresses: ["mx.advertises.example": [.v4([127, 0, 0, 1])]]
        )
        // Deliberately the plain default `DirectMXConfig()`'s
        // `tlsPolicy`/MTA-STS behavior -- no override, no policy provider
        // -- specifically to prove this is the library's *default*
        // behavior, not something that needs to be opted into. Only
        // `replyTimeout` is shortened from the 300s production default:
        // this fake server never completes a real handshake, and (exactly
        // like `serviceUnavailable421FeedsBreakerAndConnectionIsNotReturnedToIdlePool`'s
        // real-time-bounded precedent) this test only cares whether
        // STARTTLS was attempted at all, not what the connection's
        // eventual fate is -- a short timeout keeps this test fast
        // regardless of exactly how the post-`220`-then-close ambiguity
        // (a legitimate disconnect during the fenced upgrade window is
        // conservatively classified the same as a possible injection --
        // see `SMTPBootstrapHandler.errorCaught`'s own doc comment) plays
        // out on this particular run.
        let transport = DirectMXTransport(
            resolver: resolver,
            config: DirectMXConfig(port: server.port, replyTimeout: 2, allowPrivateAddresses: true),
            group: group
        )

        let envelope = try envelope(recipients: ["rcpt@advertises.example"])
        _ = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(await sawSTARTTLS.value, "the client must have sent STARTTLS by default -- no policy or explicit config was needed for the attempt itself")
    }

    // MARK: - (2) STARTTLS not advertised -> falls back to plaintext rather than failing

    @Test func aServerNotAdvertisingSTARTTLSFallsBackToPlaintextRatherThanFailingTheWholeDelivery() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await PlainAcceptingFakeSMTPServer.start(group: group)

        // `DirectMXTransport.domain(of:)` lowercases the recipient's domain
        // before grouping/resolving -- the `FakeMXResolver` dictionary key
        // must match that lowercased form exactly (an exact-match fake, no
        // case-folding of its own), so both the recipient and the
        // registered MX record key use "nostarttls.example" throughout.
        let resolver = FakeMXResolver(
            mxRecords: ["nostarttls.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.nostarttls.example")]],
            addresses: ["mx.nostarttls.example": [.v4([127, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(
            resolver: resolver, config: DirectMXConfig(port: server.port, allowPrivateAddresses: true), group: group
        )

        let envelope = try envelope(recipients: ["rcpt@nostarttls.example"])
        let results = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the opportunistic plaintext fallback, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - (3) Injection detection during the opportunistic attempt hard-fails -- never falls back to plaintext

    @Test func aGenuineSTARTTLSInjectionDuringTheOpportunisticAttemptHardFailsAndDoesNotFallBackToPlaintext() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await SameBufferInjectingFakeSMTPServer.start(group: group)

        let resolver = FakeMXResolver(
            mxRecords: ["injection.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.injection.example")]],
            addresses: ["mx.injection.example": [.v4([127, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(
            resolver: resolver, config: DirectMXConfig(port: server.port, allowPrivateAddresses: true), group: group
        )

        let envelope = try envelope(recipients: ["rcpt@injection.example"])
        let results = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .failed(let error) = results[0].outcome else {
            Issue.record("expected .failed (an injection must hard-fail, never silently degrade to plaintext delivery), got \(results[0].outcome)")
            return
        }
        guard let smtpError = error as? SMTPError, case .starttlsInjection = smtpError else {
            Issue.record("expected the failure to be classified as SMTPError.starttlsInjection specifically -- got \(error) -- a different classification here would mean the injection went undetected or was misclassified as an ordinary opportunistic-fallback trigger")
            return
        }
    }

    // MARK: - (4) FIX #1, CRITICAL (milestone security review): the pool's
    // circuit breaker must never launder a run of detected
    // STARTTLS-injection attacks into a silent plaintext downgrade.
    //
    // The real `SMTPConnectionPool` this transport owns keys its breaker by
    // `(host, port, tls)`, and `checkout` calls `recordFailure` on *any*
    // dial failure -- including a detected `.starttlsInjection` -- with no
    // distinction of cause. After `circuitBreakerThreshold` (default 5)
    // consecutive failures against `Key(host, port, tls: .startTLS)`, the
    // breaker opens; while open, the pool's breaker check throws a bare
    // `SMTPError.circuitOpen` *before ever dialing again*. Before this fix,
    // `attemptOpportunisticHostsInOrder`'s catch block only pattern-matched
    // `.starttlsInjection` specifically, so `.circuitOpen` fell through to
    // the ordinary opportunistic-fallback branch and immediately retried
    // the *same* host with `Key(host, port, tls: .none)` -- plaintext, to
    // the exact attacker-controlled path that just proved itself hostile
    // five times in a row.
    //
    // This test exercises the *real* `SMTPConnectionPool` breaker logic
    // (via `DirectMXTransport`'s production `init(resolver:config:group:...)`,
    // not the test-only injectable-dialer seam) against a real socket, the
    // same way scenario (3) above does -- the bug is specifically in the
    // interaction between the pool's breaker bookkeeping and the
    // transport's opportunistic-fallback decision, so a mock that bypasses
    // either one would not actually exercise it.

    @Test func circuitBreakerOpenedByRepeatedSTARTTLSInjectionDetectionsMustNeverLaunderIntoAPlaintextRetryAgainstTheSameHost() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let plaintextDeliveryCount = CountingFlag()
        let server = try await InjectOnSTARTTLSButPlaintextAcceptingFakeSMTPServer.start(
            group: group, onPlaintextDelivery: { await plaintextDeliveryCount.increment() }
        )

        let resolver = FakeMXResolver(
            mxRecords: ["breakerlaundering.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.breakerlaundering.example")]],
            addresses: ["mx.breakerlaundering.example": [.v4([127, 0, 0, 1])]]
        )
        // Default `.opportunistic` `tlsPolicy`, no MTA-STS policy provider
        // -- exactly the default-configuration path FIX #1's finding
        // applies to. `circuitBreakerThreshold: 5` is spelled out
        // explicitly (matching the pool's own default) so this test keeps
        // working even if that default ever changes; `circuitBreakerResetTimeout`
        // is generously long so the breaker can't coincidentally reset
        // mid-test.
        let transport = DirectMXTransport(
            resolver: resolver,
            config: DirectMXConfig(
                port: server.port,
                pool: .init(circuitBreakerThreshold: 5, circuitBreakerResetTimeout: 60),
                allowPrivateAddresses: true
            ),
            group: group
        )

        // Five consecutive deliveries to the same host, each a detected
        // STARTTLS-injection attempt -- primes the pool's real breaker for
        // `Key(host, port, tls: .startTLS)` up to (and, on the fifth, past)
        // `circuitBreakerThreshold`.
        for attempt in 1...5 {
            let recipientEnvelope = try envelope(recipients: ["rcpt\(attempt)@breakerlaundering.example"])
            let results = try await transport.send(recipientEnvelope, message())
            guard results.count == 1, case .failed(let error) = results[0].outcome,
                  let smtpError = error as? SMTPError, case .starttlsInjection = smtpError
            else {
                Issue.record("attempt \(attempt): expected a detected STARTTLS-injection failure (to prime the circuit breaker), got \(results.map(\.outcome))")
                await transport.shutdown()
                try await server.channel.close()
                try await group.shutdownGracefully()
                return
            }
        }

        // Sixth attempt: the breaker for `Key(host, port, .startTLS)` is
        // now open, so the pool's breaker check rejects with a bare
        // `SMTPError.circuitOpen` *before* ever dialing again -- the fake
        // server never even sees a sixth STARTTLS attempt. This is the
        // exact scenario the laundering bug turned into a silent plaintext
        // delivery: assert it must NOT succeed via `TLSMode.none` against
        // this host.
        let sixthEnvelope = try envelope(recipients: ["rcpt6@breakerlaundering.example"])
        let sixthResults = try await transport.send(sixthEnvelope, message())

        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(sixthResults.count == 1)
        if case .delivered = sixthResults[0].outcome {
            Issue.record(
                """
                SECURITY REGRESSION: the sixth attempt delivered successfully against a host whose circuit \
                breaker only opened because of five consecutive detected STARTTLS-injection attempts -- \
                this is the breaker-laundering bug: SMTPError.circuitOpen must never trigger an \
                opportunistic plaintext retry against the host that tripped it.
                """
            )
        }
        // The strongest possible assertion: the fake server itself must
        // never have completed a plaintext (non-STARTTLS) mail
        // transaction. A nonzero count means some attempt connected to
        // this host with `TLSMode.none` and successfully delivered in
        // cleartext -- exactly the downgrade this fix must prevent,
        // independent of exactly how `DeliveryResult` ends up classifying
        // it.
        #expect(
            await plaintextDeliveryCount.value == 0,
            "the fake server completed a plaintext mail transaction -- some attempt connected to the injecting host with TLSMode.none and delivered in cleartext"
        )
    }
}

/// A single-set-once, `async`-safe flag -- mirrors `STARTTLSRealSocketTests
/// .OutcomeBox`'s established shape for exactly this purpose.
private actor SeenFlag {
    private(set) var value = false
    func markSeen() { value = true }
}

// MARK: - Fake server 1: advertises STARTTLS, replies `220` to it, then
// closes without ever completing a real handshake -- same behavior as
// `STARTTLSRealSocketTests.FakeSMTPServer`, plus a callback fired the
// moment `STARTTLS` itself is received, so this test can assert the
// attempt was actually made independent of whatever `DirectMXTransport`
// ultimately classifies the resulting connection failure as (a real
// server hanging up before completing the handshake is exactly the
// ambiguous case this codebase's own fail-safe fencing conservatively
// treats as a possible injection -- see `SMTPBootstrapHandler
// .errorCaught`'s doc comment -- so this test deliberately does not assert
// on the final delivery outcome, only on whether the attempt itself
// happened).

private enum AdvertisingButNeverUpgradingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup, onSTARTTLS: @escaping @Sendable () async -> Void) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(AdvertisingHandler(onSTARTTLS: onSTARTTLS))
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class AdvertisingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private let onSTARTTLS: @Sendable () async -> Void

    init(onSTARTTLS: @escaping @Sendable () async -> Void) {
        self.onSTARTTLS = onSTARTTLS
    }

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            let callback = onSTARTTLS
            Task { await callback() }
            writeLine(context: context, "220 Ready to start TLS")
            context.close(promise: nil)
        }
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Fake server 2: never advertises STARTTLS at all, accepts a full
// plain EHLO/MAIL FROM/RCPT TO/DATA conversation -- identical in spirit to
// `DirectMXRealSocketTests.AcceptingFakeSMTPServerHandler`, redefined here
// (private to this file, matching that file's own scoping) so this test
// file doesn't reach into another test file's private types.

private enum PlainAcceptingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(PlainAcceptingHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class PlainAcceptingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private var inData = false

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        if inData {
            drainDataPhaseIfTerminated(context: context)
            return
        }
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            // Deliberately no `STARTTLS` line -- this is the one thing
            // that differs from `AdvertisingHandler` above.
            writeLine(context: context, "250 fake.example Hello")
        } else if upper.hasPrefix("MAIL FROM") {
            writeLine(context: context, "250 2.1.0 OK")
        } else if upper.hasPrefix("RCPT TO") {
            writeLine(context: context, "250 2.1.5 OK")
        } else if upper == "DATA" {
            writeLine(context: context, "354 Go ahead")
            inData = true
            drainDataPhaseIfTerminated(context: context)
        }
    }

    private func drainDataPhaseIfTerminated(context: ChannelHandlerContext) {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x2E, 0x0D, 0x0A] // "\r\n.\r\n"
        guard accumulated.readableBytesView.count >= terminator.count,
              Array(accumulated.readableBytesView.suffix(terminator.count)) == terminator
        else { return }
        accumulated.moveReaderIndex(forwardBy: accumulated.readableBytes)
        inData = false
        writeLine(context: context, "250 2.0.0 Queued as 12345")
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Fake server 3: the CVE-2026-41319-class same-buffer injection --
// advertises STARTTLS, then replies to the client's `STARTTLS` command with
// the `220` and an injected command concatenated into **one** write (one
// `ByteBuffer`, one `writeAndFlush` call), mirroring `STARTTLSTests
// .sameBufferInjectionIsRejected`'s fixture shape but over a real socket
// instead of `EmbeddedChannel`.

private enum SameBufferInjectingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(SameBufferInjectingHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class SameBufferInjectingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            // The attack: the `220` reply and a would-be post-upgrade
            // command are written as one buffer, one flush -- exactly the
            // same-buffer injection shape `SMTPBootstrapHandler`'s
            // residual-bytes check (plan §4.3 step 3) exists to catch.
            var buffer = context.channel.allocator.buffer(capacity: 64)
            buffer.writeString("220 Ready to start TLS\r\n")
            buffer.writeString("EHLO evil.example\r\n")
            context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        }
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Fake server 4 (FIX #1 regression test): combines fake server 3's
// same-buffer injection-on-STARTTLS behavior with fake server 2's plain
// full-transaction acceptance -- modeling the real-world danger this fix
// closes: an on-path attacker who injects when the victim attempts
// STARTTLS, but who can simply relay/accept a full plaintext SMTP
// transaction (capturing it in cleartext) if the victim connects with no
// STARTTLS attempt at all. Reports (via `onPlaintextDelivery`) whenever a
// full mail transaction completes on a connection that never sent
// `STARTTLS` -- the direct, server-side signal that a plaintext delivery
// actually reached this host.

private enum InjectOnSTARTTLSButPlaintextAcceptingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup, onPlaintextDelivery: @escaping @Sendable () async -> Void) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(InjectOnSTARTTLSButAcceptPlaintextHandler(onPlaintextDelivery: onPlaintextDelivery))
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class InjectOnSTARTTLSButAcceptPlaintextHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private var inData = false
    private var usedSTARTTLS = false
    private let onPlaintextDelivery: @Sendable () async -> Void

    init(onPlaintextDelivery: @escaping @Sendable () async -> Void) {
        self.onPlaintextDelivery = onPlaintextDelivery
    }

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        if inData {
            drainDataPhaseIfTerminated(context: context)
            return
        }
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            usedSTARTTLS = true
            // Same-buffer injection, identical shape to fake server 3.
            var buffer = context.channel.allocator.buffer(capacity: 64)
            buffer.writeString("220 Ready to start TLS\r\n")
            buffer.writeString("EHLO evil.example\r\n")
            context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        } else if upper.hasPrefix("MAIL FROM") {
            writeLine(context: context, "250 2.1.0 OK")
        } else if upper.hasPrefix("RCPT TO") {
            writeLine(context: context, "250 2.1.5 OK")
        } else if upper == "DATA" {
            writeLine(context: context, "354 Go ahead")
            inData = true
            drainDataPhaseIfTerminated(context: context)
        }
    }

    private func drainDataPhaseIfTerminated(context: ChannelHandlerContext) {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x2E, 0x0D, 0x0A] // "\r\n.\r\n"
        guard accumulated.readableBytesView.count >= terminator.count,
              Array(accumulated.readableBytesView.suffix(terminator.count)) == terminator
        else { return }
        accumulated.moveReaderIndex(forwardBy: accumulated.readableBytes)
        inData = false
        writeLine(context: context, "250 2.0.0 Queued as 12345")
        if !usedSTARTTLS {
            // This connection never attempted STARTTLS at all, yet just
            // completed a full mail transaction -- a plaintext delivery
            // reached this (attacker-controlled) host.
            let callback = onPlaintextDelivery
            Task { await callback() }
        }
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

/// A simple `async`-safe counter -- mirrors `SeenFlag`'s shape above, for
/// the FIX #1 regression test's plaintext-delivery count.
private actor CountingFlag {
    private(set) var value = 0
    func increment() { value += 1 }
}

// MARK: - Shared line-extraction helper (LF-terminated, tolerating a
// missing CR -- same simplification `STARTTLSRealSocketTests`/
// `DirectMXRealSocketTests` make, for the same reason: test-only, trusted
// input).

private func extractLine(_ buffer: inout ByteBuffer) -> String? {
    guard let lfIndex = buffer.readableBytesView.firstIndex(of: 0x0A) else { return nil }
    let length = lfIndex - buffer.readerIndex
    guard let bytes = buffer.readBytes(length: length) else { return nil }
    buffer.moveReaderIndex(forwardBy: 1)
    var text = String(decoding: bytes, as: UTF8.self)
    if text.hasSuffix("\r") { text.removeLast() }
    return text
}

private enum FakeServerError: Error {
    case noLocalPort
}

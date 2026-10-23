//
//  DirectMXMTASTSEnforceTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4: `DirectMXTransport`'s MTA-STS `enforce`/`testing`
//  routing and hard-fail logic -- the actual Phase 4 deliverable this
//  phase is responsible for (host selection, host restriction,
//  enforce-mode hard-fail, testing-mode never-blocks-delivery fallback).
//
//  **Scope note, a deliberate judgment call (documented per this task's
//  own instructions, not silently made):** these tests use
//  `DirectMXTransport`'s test-only injectable-dialer `init` (the same seam
//  `DirectMXTransportTests.swift` uses throughout), scripted with
//  `ConnectionHarness`-backed in-memory connections -- **not** a real
//  socket / real NIOSSL handshake. A genuinely successful, certificate-
//  verified TLS connection cannot currently be exercised end-to-end in
//  this test suite for a *self-signed* test certificate: `makeDialer`
//  always builds its `TLSConfiguration` via `.makeClientConfiguration()`
//  (full system trust-root verification, correctly -- that's the whole
//  point of `.startTLS` being mandatory-verified), and neither
//  `DirectMXConfig` nor `SMTPBootstrap.connect`'s call site here exposes a
//  way to inject a custom trust root for a test-only self-signed
//  certificate to verify against. What these tests verify instead -- and
//  what is actually Phase 4's own responsibility, as opposed to Phase 1's
//  already-covered STARTTLS-correctness territory (`STARTTLSRealSocketTests`,
//  `STARTTLSTests`) -- is the *routing/enforcement logic*: which `(host,
//  TLSMode)` pool keys `DirectMXTransport` does and does not attempt for a
//  given MTA-STS policy, and how it classifies the outcome. A connection
//  the scripted dialer hands back for a given key models "this key's
//  connection attempt succeeded," abstracting over how the connection was
//  actually secured -- the genuine TLS handshake/certificate-verification
//  behavior itself is Phase 1's already-tested territory
//  (`STARTTLSRealSocketTests.swift`), not re-proven here. Flagged
//  explicitly as a known limitation for the milestone review: a follow-up
//  that threads a test-injectable `TLSConfiguration` through
//  `DirectMXConfig`/`makeDialer` would let a *future* test suite close this
//  gap with a real self-signed-cert handshake if that fidelity is judged
//  worth adding later.
//
//  Opportunistic-TLS-default behavior and the STARTTLS-injection safety
//  property use real sockets instead -- see `DirectMXOpportunisticTLSTests.swift`.
//

import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

/// A fully scripted `MTASTSPolicyProviding` fake: exact-match domain
/// lookups, `nil` for anything unregistered (matching a real
/// `MTASTSPolicyManager`'s "no usable policy" outcome for a domain that
/// doesn't publish MTA-STS at all).
struct FakeMTASTSPolicyProvider: MTASTSPolicyProviding {
    let policiesByDomain: [String: MTASTSPolicy]
    func policy(for domain: String) async -> MTASTSPolicy? { policiesByDomain[domain] }
}

struct DirectMXMTASTSEnforceTests {
    private func envelope(recipients: [String]) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: recipients)
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    // MARK: - `enforce`: a policy-mismatched MX host is never dialed

    @Test func enforceModeNeverDialsAPolicyMismatchedHost() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "enforce.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "mx1.enforce.example"),
                DNSResolver.MXRecord(preference: 20, exchange: "mx2.enforce.example"),
            ]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "enforce.example": MTASTSPolicy(mode: .enforce, mxPatterns: ["mx2.enforce.example"], maxAge: 86400),
        ])
        let succeedingHost = scriptedDialer()
        let mismatchedHostWasDialed = CallCountBox()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "mx1.enforce.example":
                await mismatchedHostWasDialed.increment()
                throw SimulatedConnectFailure(label: "mx1 must never be dialed under enforce")
            case "mx2.enforce.example":
                #expect(key.tls == .startTLS, "enforce mode must only ever use mandatory-verified STARTTLS")
                return try await succeedingHost(key)
            default:
                throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@enforce.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the policy-matched host, got \(results[0].outcome)")
            return
        }
        #expect(await mismatchedHostWasDialed.count == 0, "the policy-mismatched host must never be dialed at all under enforce mode")
    }

    // MARK: - `enforce`: no matching host at all hard-fails without dialing anything

    @Test func enforceModeHardFailsImmediatelyWhenNoResolvedHostMatchesThePolicy() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "nomatch.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx1.nomatch.example")]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "nomatch.example": MTASTSPolicy(mode: .enforce, mxPatterns: ["mx9.completely-different.example"], maxAge: 86400),
        ])
        // Any dial attempt at all is a bug for this test -- with zero
        // policy-matching hosts, `enforce` mode must hard-fail before ever
        // reaching the connection pool.
        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider,
            dialer: failingDialer(label: "must never be called -- no host matched the enforce policy")
        )

        let results = try await transport.send(try envelope(recipients: ["rcpt@nomatch.example"]), message())

        #expect(results.count == 1)
        // Release review: an enforce violation is temporary (RFC 8461 §5:
        // don't deliver to it now; a later attempt may succeed).
        guard case .queuedForRetry(_, _, let reply) = results[0].outcome else {
            Issue.record("expected a temporary failure, got \(results[0].outcome)")
            return
        }
        #expect(reply.code == 451)
        #expect(reply.lines.first?.contains("4.7.5") == true)
    }

    // MARK: - `enforce`: a policy-matched host without valid TLS hard-fails, never falls back to plaintext

    @Test func enforceModeHardFailsOnAMatchedHostsTLSFailureRatherThanFallingBackToPlaintext() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "tlsfail.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.tlsfail.example")]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "tlsfail.example": MTASTSPolicy(mode: .enforce, mxPatterns: ["mx.tlsfail.example"], maxAge: 86400),
        ])
        let plaintextWasAttempted = CallCountBox()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            if key.tls == .none {
                await plaintextWasAttempted.increment()
                throw SimulatedConnectFailure(label: "enforce mode must never attempt plaintext")
            }
            #expect(key.tls == .startTLS)
            throw SimulatedConnectFailure(label: "simulated STARTTLS/handshake failure")
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@tlsfail.example"]), message())

        #expect(results.count == 1)
        guard case .queuedForRetry(_, _, let reply) = results[0].outcome else {
            Issue.record("expected a temporary policy failure, not a plaintext-fallback delivery, got \(results[0].outcome)")
            return
        }
        #expect(reply.lines.first?.contains("4.7.5") == true)
        #expect(await plaintextWasAttempted.count == 0, "enforce mode must never attempt a plaintext (.none) connection")
    }

    // MARK: - `enforce`: a policy-matched host with a successful connection delivers normally

    @Test func enforceModeDeliversNormallyThroughAPolicyMatchedHost() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "works.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.works.example")]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "works.example": MTASTSPolicy(mode: .enforce, mxPatterns: ["mx.works.example"], maxAge: 86400),
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            #expect(key.tls == .startTLS)
            return try await succeedingHost(key)
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@works.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - `testing`: a TLS-specific failure against a policy-matched host falls back to unconstrained delivery

    @Test func testingModeFallsBackToUnconstrainedOpportunisticDeliveryWhenThePolicyMatchedAttemptFails() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "testing.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "mx1.testing.example"), // matches the policy, but fails
                DNSResolver.MXRecord(preference: 20, exchange: "mx2.testing.example"), // doesn't match, but works
            ]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "testing.example": MTASTSPolicy(mode: .testing, mxPatterns: ["mx1.testing.example"], maxAge: 86400),
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "mx1.testing.example":
                // Fails regardless of TLS mode -- `testing` mode's own
                // mandatory-TLS attempt against this host fails, and (were
                // it ever retried opportunistically, which it should not
                // need to be for this test to still pass, since mx2 is the
                // one that ultimately succeeds) it would fail there too.
                throw SimulatedConnectFailure(label: "mx1 always fails")
            case "mx2.testing.example":
                return try await succeedingHost(key)
            default:
                throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@testing.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("testing mode must never block delivery -- expected .delivered via the unconstrained opportunistic fallback, got \(results[0].outcome)")
            return
        }
    }

    @Test func testingModeSucceedsDirectlyThroughAPolicyMatchedHostWithoutNeedingAnyFallback() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "testingworks.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.testingworks.example")]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "testingworks.example": MTASTSPolicy(mode: .testing, mxPatterns: ["mx.testingworks.example"], maxAge: 86400),
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            #expect(key.tls == .startTLS)
            return try await succeedingHost(key)
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@testingworks.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - No policy at all / `mode: none`: unaffected by MTA-STS, same opportunistic default

    @Test func aDomainWithNoMTASTSPolicyIsUnaffectedByAConfiguredPolicyProvider() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "nopolicy.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.nopolicy.example")]
        ])
        // Provider configured, but has no entry for this domain at all --
        // matches a real `MTASTSPolicyManager` returning `nil` for a domain
        // that doesn't publish MTA-STS.
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [:])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            try await succeedingHost(key)
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@nopolicy.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered, got \(results[0].outcome)")
            return
        }
    }

    @Test func aModeNonePolicyIsTreatedIdenticallyToNoPolicyAtAll() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "modenone.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.modenone.example")]
        ])
        let policyProvider = FakeMTASTSPolicyProvider(policiesByDomain: [
            "modenone.example": MTASTSPolicy(mode: .none, mxPatterns: [], maxAge: 86400),
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            try await succeedingHost(key)
        }

        let transport = DirectMXTransport(
            resolver: resolver, group: NIOAsyncTestingEventLoop(), mtaSTSPolicyProvider: policyProvider, dialer: dialer
        )
        let results = try await transport.send(try envelope(recipients: ["rcpt@modenone.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered, got \(results[0].outcome)")
            return
        }
    }
}

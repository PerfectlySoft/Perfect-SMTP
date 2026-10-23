//
//  DirectMXFailureClassificationTests.swift
//  PerfectSMTPTests
//
//  Release review: DirectMX used to report every connection-level failure
//  as a final `.failed`, so nothing was ever retried. Following RFC 5321
//  §4.5.4.1, unreachable hosts, timeouts, an open breaker, TLS failures and
//  DNS timeouts/SERVFAIL are now temporary (`.queuedForRetry`, and queued);
//  NXDOMAIN, null MX and 5yz stay final. Also pins down when opportunistic
//  TLS falls back to plaintext and when it never does.
//

import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DirectMXFailureClassificationTests {
    private func envelope(_ recipient: String) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: [recipient])
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    private static let mx = FakeMXResolver(mxRecords: [
        "dest.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.dest.example")],
    ], addresses: ["mx.dest.example": [.v4([127, 0, 0, 1])]])

    // MARK: - The classification table

    @Test(arguments: [
        ("connect timeout", ChannelError.connectTimeout(.seconds(1)) as any Error, true),
        ("connection refused", IOError(errnoCode: ECONNREFUSED, reason: "connect"), true),
        ("reply timeout", SMTPConnectionError.replyTimedOut, true),
        ("peer hung up", SMTPConnectionError.channelClosedByPeer, true),
        ("circuit open", SMTPError.circuitOpen, true),
        ("STARTTLS missing", SMTPError.starttlsRequired, true),
        ("certificate", SMTPError.tlsCertificateInvalid(underlying: nil), true),
        ("injection", SMTPError.starttlsInjection(underlying: nil), true),
        ("wrapped timeout", SMTPError.connectionFailed(SMTPConnectionError.replyTimedOut), true),
        ("DNS timeout", DNSResolver.ResolveError.timeout, true),
        ("DNS SERVFAIL", DNSResolver.ResolveError.serverFailure(rcode: 2), true),
        ("NXDOMAIN", DNSResolver.ResolveError.noRecordsFound, false),
        ("null MX", DNSResolver.ResolveError.nullMX, false),
        ("private address", DirectMXError.allResolvedAddressesFilteredAsPrivate(host: "mx"), false),
        ("bad host name", AddressSyntax.Error.invalidHostname(field: "MX host"), false),
        ("5yz", SMTPError.permanentFailure(SMTPReply(code: 550, lines: ["no"])), false),
    ])
    func connectionFailuresAreClassifiedPerRFC5321(label: String, error: any Error, transient: Bool) {
        #expect(DirectMXTransport.isTransientConnectionFailure(error) == transient, "\(label)")
        let outcome = DirectMXTransport.classify(connectionFailure: error, domain: "dest.example", retryQueueConfiguration: .init())
        if transient {
            guard case .queuedForRetry(_, _, let last) = outcome else {
                Issue.record("\(label): expected .queuedForRetry, got \(outcome)")
                return
            }
            #expect(last.code == 451)
        } else {
            guard case .failed = outcome else {
                Issue.record("\(label): expected .failed, got \(outcome)")
                return
            }
        }
    }

    // MARK: - End to end

    @Test func anUnreachableHostIsQueuedForRetry() async throws {
        let transport = DirectMXTransport(
            resolver: Self.mx, config: DirectMXConfig(tlsPolicy: .fixed(.none)), group: NIOAsyncTestingEventLoop()
        ) { _ in throw ChannelError.connectTimeout(.seconds(30)) }
        let results = try await transport.send(try envelope("rcpt@dest.example"), message())
        guard case .queuedForRetry? = results.first?.outcome else {
            Issue.record("expected .queuedForRetry, got \(String(describing: results.first?.outcome))")
            return
        }
        #expect(await transport.pendingRetryEntries().count == 1)
        await transport.shutdown()
    }

    /// A real refused connect: a port on 127.0.0.1 with nothing listening.
    @Test func aRealRefusedConnectionIsQueuedForRetry() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
        let port = try #require(probe.localAddress?.port)
        try await probe.close()

        let transport = DirectMXTransport(
            resolver: Self.mx,
            config: DirectMXConfig(port: port, tlsPolicy: .fixed(.none), connectTimeout: .seconds(5), allowPrivateAddresses: true),
            group: group
        )
        let results = try await transport.send(try envelope("rcpt@dest.example"), message())
        await transport.shutdown()
        try await group.shutdownGracefully()
        guard case .queuedForRetry(_, _, let last)? = results.first?.outcome else {
            Issue.record("expected .queuedForRetry, got \(String(describing: results.first?.outcome))")
            return
        }
        #expect(last.lines.joined().contains("4.4.1"))
    }

    @Test func aDNSTimeoutResolvingTheMXHostIsQueuedButNXDOMAINIsFinal() async throws {
        struct Resolver: MXResolving {
            let error: DNSResolver.ResolveError
            func resolveMX(domain: String) async throws -> [DNSResolver.MXRecord] { [.init(preference: 10, exchange: "mx.dest.example")] }
            func resolveAddresses(hostname: String) async throws -> [DNSAddress] { throw error }
        }
        for (error, transient) in [(DNSResolver.ResolveError.timeout, true), (.serverFailure(rcode: 2), true), (.noRecordsFound, false)] {
            let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            let transport = DirectMXTransport(resolver: Resolver(error: error), config: DirectMXConfig(tlsPolicy: .fixed(.none)), group: group)
            let results = try await transport.send(try envelope("rcpt@dest.example"), message())
            await transport.shutdown()
            try await group.shutdownGracefully()
            switch results.first?.outcome {
            case .queuedForRetry?: #expect(transient, "\(error) should be final")
            case .failed?: #expect(!transient, "\(error) should be retried")
            default: Issue.record("\(error): unexpected \(String(describing: results.first?.outcome))")
            }
        }
    }

    // MARK: - When opportunistic TLS falls back to plaintext

    private actor KeyLog {
        private(set) var keys: [SMTPConnectionPool.Key] = []
        func record(_ key: SMTPConnectionPool.Key) { keys.append(key) }
        var plaintextAttempts: Int { keys.filter { $0.tls == .none }.count }
    }

    private func dial(
        policy: DirectMXTLSPolicy, mtaSTS: MTASTSPolicy? = nil, startTLSFailure: any Error & Sendable
    ) async throws -> (log: KeyLog, outcome: DeliveryResult.Outcome?) {
        let log = KeyLog()
        let provider = mtaSTS.map { FakeMTASTSPolicyProvider(policiesByDomain: ["dest.example": $0]) }
        let transport = DirectMXTransport(
            resolver: Self.mx, config: DirectMXConfig(tlsPolicy: policy), group: NIOAsyncTestingEventLoop(),
            mtaSTSPolicyProvider: provider
        ) { key in
            await log.record(key)
            if key.tls == .startTLS { throw startTLSFailure }
            throw SimulatedConnectFailure(label: "plaintext attempt")
        }
        let results = try await transport.send(try envelope("rcpt@dest.example"), message())
        await transport.shutdown()
        return (log, results.first?.outcome)
    }

    /// No policy: a 454 reply to STARTTLS, a failed handshake or a bad
    /// certificate falls back to plaintext on the same host (what an
    /// attacker able to break TLS could force anyway by stripping STARTTLS).
    @Test(arguments: [
        SMTPError.transientFailure(SMTPReply(code: 454, lines: ["4.7.0 TLS not available"])),
        SMTPError.tlsCertificateInvalid(underlying: nil),
        SMTPError.starttlsRequired,
        SMTPError.connectionFailed(ChannelError.connectTimeout(.seconds(1))),
    ])
    func opportunisticFallsBackToPlaintextWithoutAPolicy(failure: SMTPError) async throws {
        let (log, _) = try await dial(policy: .opportunistic, startTLSFailure: failure)
        #expect(await log.plaintextAttempts == 1, "\(failure)")
    }

    /// ...but never after detected injection or an open breaker.
    @Test(arguments: [SMTPError.starttlsInjection(underlying: nil), .circuitOpen])
    func opportunisticNeverFallsBackAfterInjectionOrAnOpenBreaker(failure: SMTPError) async throws {
        let (log, outcome) = try await dial(policy: .opportunistic, startTLSFailure: failure)
        #expect(await log.plaintextAttempts == 0)
        guard case .queuedForRetry? = outcome else {
            Issue.record("expected .queuedForRetry, got \(String(describing: outcome))")
            return
        }
    }

    /// Required TLS (`.fixed(.startTLS)`) and MTA-STS enforce never fall
    /// back, whatever the failure.
    @Test(arguments: [
        SMTPError.transientFailure(SMTPReply(code: 454, lines: ["4.7.0 TLS not available"])),
        SMTPError.tlsCertificateInvalid(underlying: nil),
        SMTPError.starttlsRequired,
    ])
    func requiredTLSAndEnforceNeverFallBack(failure: SMTPError) async throws {
        let (fixedLog, fixedOutcome) = try await dial(policy: .fixed(.startTLS), startTLSFailure: failure)
        #expect(await fixedLog.plaintextAttempts == 0)
        guard case .queuedForRetry? = fixedOutcome else {
            Issue.record("fixed(.startTLS): expected .queuedForRetry, got \(String(describing: fixedOutcome))")
            return
        }

        let enforce = MTASTSPolicy(mode: .enforce, mxPatterns: ["mx.dest.example"], maxAge: 86400)
        let (enforceLog, enforceOutcome) = try await dial(policy: .opportunistic, mtaSTS: enforce, startTLSFailure: failure)
        #expect(await enforceLog.plaintextAttempts == 0)
        #expect(await enforceLog.keys.allSatisfy { $0.requireCertificateDNSName })
        guard case .queuedForRetry(_, _, let last)? = enforceOutcome, last.lines.joined().contains("4.7.5") else {
            Issue.record("enforce: expected a 4.7.5 temporary failure, got \(String(describing: enforceOutcome))")
            return
        }
    }

    /// Testing mode tries the policy hosts with the DNS-name check first,
    /// then falls through to ordinary opportunistic delivery (RFC 8461 §5:
    /// testing never blocks).
    @Test func testingModeRequiresTheDNSNameFirstThenFallsThrough() async throws {
        let testing = MTASTSPolicy(mode: .testing, mxPatterns: ["mx.dest.example"], maxAge: 86400)
        let (log, _) = try await dial(policy: .opportunistic, mtaSTS: testing, startTLSFailure: SMTPError.tlsCertificateInvalid(underlying: nil))
        let keys = await log.keys
        #expect(keys.first?.requireCertificateDNSName == true)
        #expect(keys.contains { $0.tls == .startTLS && !$0.requireCertificateDNSName })
        #expect(await log.plaintextAttempts == 1)
    }
}

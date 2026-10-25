//
//  STARTTLSCertificateTests.swift
//  PerfectSMTPTests
//
//  Release review: certificate name checking for STARTTLS, against a real
//  TLS-speaking fake server on 127.0.0.1 with a local test CA
//  (`TestCertificates`).
//
//  - Only a genuine IP literal is dialed without SNI. Any other name
//    NIOSSL refuses for SNI (the reviewer used `mx\0.victim.test`) used to
//    fall back to checking the IP, so a certificate with just an IP SAN
//    passed.
//  - Under MTA-STS (`requireCertificateDNSName`), the certificate needs a
//    DNS SAN for the MX host; an IP SAN alone is refused.
//  - Certificate failures surface as `.tlsCertificateInvalid`, not as
//    `.starttlsInjection`.
//

import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import Testing
@testable import PerfectSMTP

// Serialized: every case is a TLS handshake (and some load the system
// trust store). Run all at once on a slow machine (emulated amd64 debug)
// they starve the timing-sensitive tests running alongside.
@Suite(.serialized)
struct STARTTLSCertificateTests {
    enum Leaf { case ipOnly, named, dnsOnly }

    private func clientTLS() throws -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(TestCertificates.caPEM.utf8), format: .pem)])
        return configuration
    }

    /// Runs one STARTTLS bootstrap against a fresh server presenting
    /// `leaf`, returning the error (or nil on success).
    private func bootstrap(
        leaf: Leaf, sniHostname: String, requireDNSName: Bool = false, tls: TLSMode = .startTLS
    ) async throws -> (any Error)? {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await TLSFakeSMTPServer.start(leaf: leaf, implicit: tls == .implicit, group: group)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: server.port)
        var failure: (any Error)?
        do {
            let channel = try await SMTPBootstrap.connect(
                to: address, sniHostname: sniHostname, tls: tls, replyTimeout: 10,
                tlsConfiguration: try clientTLS(), requireCertificateDNSName: requireDNSName, group: group
            )
            try? await channel.channel.close()
        } catch {
            failure = error
        }
        try? await server.channel.close()
        try await group.shutdownGracefully()
        return failure
    }

    private func isCertificateInvalid(_ error: (any Error)?) -> Bool {
        if case SMTPError.tlsCertificateInvalid? = error { return true }
        return false
    }

    @Test(.timeLimit(.minutes(1)))
    func aMatchingDNSNameConnects() async throws {
        #expect(try await bootstrap(leaf: .named, sniHostname: "mx.victim.test") == nil)
        #expect(try await bootstrap(leaf: .named, sniHostname: "mx.victim.test", requireDNSName: true) == nil)
        #expect(try await bootstrap(leaf: .named, sniHostname: "mx.victim.test", tls: .implicit) == nil)
    }

    @Test(.timeLimit(.minutes(1)))
    func anIPLiteralIsCheckedAgainstAnIPSubjectAltName() async throws {
        #expect(try await bootstrap(leaf: .ipOnly, sniHostname: "127.0.0.1") == nil)
    }

    /// The reviewer's case: a NUL in the name made NIOSSL refuse it for
    /// SNI, the old fallback verified the IP instead, and the IP-only
    /// certificate passed for "mx\0.victim.test".
    @Test(.timeLimit(.minutes(1)), arguments: ["mx\u{0}.victim.test", "mx.victim.test.", "mx victim.test"])
    func aNameThatIsNotAHostnameIsRefusedInsteadOfFallingBackToTheIP(name: String) async throws {
        let error = try await bootstrap(leaf: .ipOnly, sniHostname: name)
        #expect(error != nil, "connected with sni=\(name.debugDescription)")
    }

    /// NIOSSL accepts an iPAddress SAN equal to the dialed address even when
    /// a host name is expected (RFC 6125 permits either identifier). For
    /// relays and opportunistic direct MX that stays as is; under MTA-STS
    /// the DNS name is required (below).
    @Test(.timeLimit(.minutes(1)))
    func anIPOnlyCertificateMatchingTheDialedAddressNeedsTheMTASTSCheckToBeRefused() async throws {
        #expect(try await bootstrap(leaf: .ipOnly, sniHostname: "mx.victim.test") == nil)
        let error = try await bootstrap(leaf: .ipOnly, sniHostname: "mx.victim.test", requireDNSName: true)
        #expect(isCertificateInvalid(error), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aWrongDNSNameIsACertificateFailureNotAnInjection() async throws {
        #expect(try await bootstrap(leaf: .dnsOnly, sniHostname: "mx.victim.test") == nil)
        let error = try await bootstrap(leaf: .dnsOnly, sniHostname: "mx2.victim.test")
        #expect(isCertificateInvalid(error), "got \(String(describing: error))")
        let implicit = try await bootstrap(leaf: .dnsOnly, sniHostname: "mx2.victim.test", tls: .implicit)
        #expect(isCertificateInvalid(implicit), "got \(String(describing: implicit))")
    }

    /// MTA-STS: an IP literal can't satisfy the DNS-name requirement, and
    /// a certificate valid only through its IP SAN is refused even if the
    /// chain verifies.
    @Test(.timeLimit(.minutes(1)))
    func underMTASTSAnIPSubjectAltNameAloneIsRefused() async throws {
        let literal = try await bootstrap(leaf: .ipOnly, sniHostname: "127.0.0.1", requireDNSName: true)
        #expect(isCertificateInvalid(literal), "got \(String(describing: literal))")
        let named = try await bootstrap(leaf: .named, sniHostname: "127.0.0.1", requireDNSName: true)
        #expect(isCertificateInvalid(named), "got \(String(describing: named))")
    }

    @Test(.timeLimit(.minutes(1)))
    func anUntrustedChainIsACertificateFailure() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await TLSFakeSMTPServer.start(leaf: .named, implicit: false, group: group)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: server.port)
        var failure: (any Error)?
        do {
            // The default trust store doesn't know the test CA.
            _ = try await SMTPBootstrap.connect(to: address, sniHostname: "mx.victim.test", tls: .startTLS, replyTimeout: 10, group: group)
        } catch {
            failure = error
        }
        try? await server.channel.close()
        try await group.shutdownGracefully()
        #expect(isCertificateInvalid(failure), "got \(String(describing: failure))")
    }
}

/// A fake SMTP server that really speaks TLS: STARTTLS (or implicit TLS
/// from the first byte) with the chosen test certificate.
enum TLSFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(leaf: STARTTLSCertificateTests.Leaf, implicit: Bool, group: any EventLoopGroup) async throws -> Running {
        let (certPEM, keyPEM): (String, String)
        switch leaf {
        case .ipOnly: (certPEM, keyPEM) = (TestCertificates.ipOnlyCertificatePEM, TestCertificates.ipOnlyKeyPEM)
        case .named: (certPEM, keyPEM) = (TestCertificates.namedCertificatePEM, TestCertificates.namedKeyPEM)
        case .dnsOnly: (certPEM, keyPEM) = (TestCertificates.dnsOnlyCertificatePEM, TestCertificates.dnsOnlyKeyPEM)
        }
        let configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: Array(certPEM.utf8), format: .pem))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem))
        )
        let context = try NIOSSLContext(configuration: configuration)
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if implicit {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    }
                    try channel.pipeline.syncOperations.addHandler(TLSFakeSMTPHandler(context: context, implicit: implicit))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw ServerError.noPort }
        return Running(channel: channel, port: port)
    }

    enum ServerError: Error { case noPort }
}

private final class TLSFakeSMTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    // Event-loop confined.
    private let sslContext: NIOSSLContext
    private let implicit: Bool
    private var buffer = ByteBuffer()
    private var upgraded = false

    init(context: NIOSSLContext, implicit: Bool) {
        self.sslContext = context
        self.implicit = implicit
        self.upgraded = implicit
    }

    func channelActive(context: ChannelHandlerContext) {
        write(context, "220 fake.victim.test ESMTP")
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)
        while let lf = buffer.readableBytesView.firstIndex(of: 0x0A) {
            let bytes = buffer.readBytes(length: lf - buffer.readerIndex + 1) ?? []
            let line = String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            if line.hasPrefix("EHLO") {
                write(context, "250-fake.victim.test")
                write(context, upgraded ? "250 PIPELINING" : "250 STARTTLS")
            } else if line == "STARTTLS", !upgraded {
                write(context, "220 Ready to start TLS")
                upgraded = true
                try? context.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: sslContext), position: .first)
            } else if line == "QUIT" {
                write(context, "221 bye")
                context.close(promise: nil)
            } else {
                write(context, "250 OK")
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }

    private func write(_ context: ChannelHandlerContext, _ line: String) {
        context.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(string: line + "\r\n")), promise: nil)
    }
}

/// Release review: every relay TLS connection to a host name needs a DNS
/// subjectAltName, so a DNS attacker holding an IP certificate for the
/// address they redirect to can't collect AUTH credentials.
@Suite(.serialized)
struct RelayCertificateNameTests {
    @Test func theDefaultDialerRequiresADNSNameForTLSToAHostName() {
        typealias Key = SMTPConnectionPool.Key
        #expect(SMTPConnectionPool.requiresCertificateDNSName(Key(host: "smtp.example.com", port: 587, tls: .startTLS)))
        #expect(SMTPConnectionPool.requiresCertificateDNSName(Key(host: "smtp.example.com", port: 465, tls: .implicit)))
        #expect(!SMTPConnectionPool.requiresCertificateDNSName(Key(host: "192.0.2.10", port: 465, tls: .implicit)))
        #expect(!SMTPConnectionPool.requiresCertificateDNSName(Key(host: "smtp.example.com", port: 25, tls: .none)))
    }

    /// The attack itself, by name (localhost resolves without DNS): an
    /// IP-only certificate for the dialed address passes NIOSSL's check,
    /// and only the DNS-name requirement refuses it.
    @Test(.timeLimit(.minutes(1)), arguments: [TLSMode.startTLS, .implicit])
    func anIPOnlyCertificateForARelayHostNameIsRefused(tls: TLSMode) async throws {
        func connect(host: String = "localhost", require: Bool) async throws -> (any Error)? {
            let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            let server = try await TLSFakeSMTPServer.start(leaf: .ipOnly, implicit: tls == .implicit, group: group)
            var configuration = TLSConfiguration.makeClientConfiguration()
            configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(TestCertificates.caPEM.utf8), format: .pem)])
            var failure: (any Error)?
            do {
                let channel = try await SMTPBootstrap.connect(
                    host: host, port: server.port, tls: tls, replyTimeout: 10,
                    tlsConfiguration: configuration, requireCertificateDNSName: require, group: group
                )
                try? await channel.channel.close()
            } catch { failure = error }
            try? await server.channel.close()
            try await group.shutdownGracefully()
            return failure
        }
        // NIOSSL alone accepts the IP certificate for the name...
        #expect(try await connect(require: false) == nil)
        // ...the DNS-name requirement refuses it...
        let refused = try await connect(require: true)
        guard case SMTPError.tlsCertificateInvalid? = refused else {
            Issue.record("expected tlsCertificateInvalid, got \(String(describing: refused))")
            return
        }
        // ...and an IP-literal relay is still checked against its IP SAN.
        #expect(try await connect(host: "127.0.0.1", require: false) == nil)
    }
}

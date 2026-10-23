//
//  MTASTSHTTPFetcherSizeLimitTests.swift
//  PerfectSMTPTests
//
//  Release review: `URLSessionMTASTSFetcher` used to buffer the whole body
//  before `MTASTSPolicyManager` checked the 64 KiB cap, so a policy host
//  streaming an endless body drove memory without bound (3 GB read, 2 GB
//  peak RSS in the reviewer's repro). The cap is now enforced while
//  streaming, and a larger Content-Length is refused before the body.
//  Runs against local servers on 127.0.0.1.
//

import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL
import Testing
@testable import PerfectSMTP

/// The fetchers under test. On Linux, `URLSessionMTASTSFetcher` can't stop
/// corelibs Foundation from reading and queueing an endless body after
/// cancelling (5.9 GB RSS and an OOM kill on linux/amd64), so there only
/// the NIO fetcher, the default, is held to the cap.
enum FetcherKind: String, CaseIterable, Sendable {
    case nio, urlSession

    static var cappedOnThisPlatform: [FetcherKind] {
        #if canImport(FoundationNetworking)
        [.nio]
        #else
        allCases
        #endif
    }

    func make(timeout: TimeInterval = 30) -> any MTASTSHTTPFetching {
        switch self {
        // The local test servers are on 127.0.0.1, which the address
        // vetting would (rightly) refuse.
        case .nio: NIOMTASTSHTTPFetcher(timeout: timeout, allowPrivateAddresses: true)
        case .urlSession: URLSessionMTASTSFetcher(timeout: timeout)
        }
    }
}

struct MTASTSHTTPFetcherSizeLimitTests {
    @Test(.timeLimit(.minutes(1)), arguments: FetcherKind.cappedOnThisPlatform, [false, true])
    func anEndlessBodyIsCutOffAtTheCapWithoutBufferingIt(kind: FetcherKind, declareHugeLength: Bool) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sent = NIOLockedValueBox(0)
        let closed = NIOLockedValueBox(false)
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        EndlessBodyHTTPHandler(declareHugeLength: declareHugeLength, sent: sent, closed: closed)
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        let port = try #require(channel.localAddress?.port)

        let fetcher = kind.make()
        let url = try #require(URL(string: "http://127.0.0.1:\(port)/.well-known/mta-sts.txt"))
        let started = Date()
        await #expect(throws: MTASTSHTTPFetchError.responseTooLarge(limit: MTASTSPolicyManager.maximumPolicyResponseSizeBytes)) {
            _ = try await fetcher.fetch(url: url)
        }
        #expect(Date().timeIntervalSince(started) < 10)

        // The client must hang up rather than keep draining the body:
        // wait for the server to see the connection close, then check the
        // server didn't get far ahead (socket buffers allow some slack).
        let deadline = Date().addingTimeInterval(10)
        while !closed.withLockedValue({ $0 }), Date() < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let total = sent.withLockedValue { $0 }
        try await channel.close()
        try await group.shutdownGracefully()
        #expect(closed.withLockedValue { $0 }, "the client never closed the connection; the server streamed \(total) bytes")
        #expect(total < 256 * 1024 * 1024, "the server streamed \(total) bytes before the client stopped reading")
    }

    @Test func aPolicyManagerTreatsAnOversizedFetchAsNoPolicy() async throws {
        struct Oversized: MTASTSHTTPFetching {
            func fetch(url: URL) async throws -> MTASTSHTTPResponse {
                throw MTASTSHTTPFetchError.responseTooLarge(limit: 1)
            }
        }
        struct TXT: TXTResolving {
            func resolveTXT(name: String) async throws -> [String] { ["v=STSv1; id=1"] }
        }
        let manager = MTASTSPolicyManager(dnsResolver: TXT(), httpFetcher: Oversized())
        #expect(await manager.policy(for: "example.test") == nil)
    }
}

/// Answers any request with a 200 and then writes 64 KiB chunks for as
/// long as the client keeps reading, counting what it sent.
private final class EndlessBodyHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    // Event-loop confined.
    private let declareHugeLength: Bool
    private let sent: NIOLockedValueBox<Int>
    private let closed: NIOLockedValueBox<Bool>
    private var started = false
    private let chunk = ByteBuffer(repeating: UInt8(ascii: "#"), count: 64 * 1024)

    init(declareHugeLength: Bool, sent: NIOLockedValueBox<Int>, closed: NIOLockedValueBox<Bool>) {
        self.declareHugeLength = declareHugeLength
        self.sent = sent
        self.closed = closed
    }

    func channelInactive(context: ChannelHandlerContext) {
        closed.withLockedValue { $0 = true }
        context.fireChannelInactive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !started else { return }
        started = true
        let length = declareHugeLength ? "Content-Length: 10000000000\r\n" : ""
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\(length)Connection: close\r\n\r\nversion: STSv1\n"
        context.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(string: head)), promise: nil)
        writeMore(context: context)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if started { writeMore(context: context) }
        context.fireChannelWritabilityChanged()
    }

    private func writeMore(context: ChannelHandlerContext) {
        while context.channel.isActive, context.channel.isWritable {
            sent.withLockedValue { $0 += chunk.readableBytes }
            context.writeAndFlush(Self.wrapOutboundOut(chunk), promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}

/// The NIO fetcher end to end: a real policy over HTTPS (local test CA),
/// a chunked body, and an untrusted certificate.
@Suite(.serialized)
struct NIOMTASTSHTTPFetcherTests {
    private static let policy = "version: STSv1\r\nmode: enforce\r\nmx: mx.victim.test\r\nmax_age: 86400\r\n"

    private func serve(leaf: STARTTLSCertificateTests.Leaf, group: any EventLoopGroup) async throws -> (Channel, Int) {
        try await serve(tls: true, chunked: false, leaf: leaf, group: group)
    }

    private func serve(tls: Bool, chunked: Bool, leaf: STARTTLSCertificateTests.Leaf = .named, group: any EventLoopGroup) async throws -> (Channel, Int) {
        let (certPEM, keyPEM): (String, String)
        switch leaf {
        case .ipOnly: (certPEM, keyPEM) = (TestCertificates.ipOnlyCertificatePEM, TestCertificates.ipOnlyKeyPEM)
        case .named: (certPEM, keyPEM) = (TestCertificates.namedCertificatePEM, TestCertificates.namedKeyPEM)
        case .dnsOnly: (certPEM, keyPEM) = (TestCertificates.dnsOnlyCertificatePEM, TestCertificates.dnsOnlyKeyPEM)
        }
        let context: NIOSSLContext? = tls ? try NIOSSLContext(configuration: .makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: Array(certPEM.utf8), format: .pem))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem))
        )) : nil
        let body = Self.policy
        let bytes = Array(body.utf8)
        let first = String(decoding: bytes[..<(bytes.count / 2)], as: UTF8.self)
        let second = String(decoding: bytes[(bytes.count / 2)...], as: UTF8.self)
        let response = chunked
            ? "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                + "\(String(first.utf8.count, radix: 16))\r\n\(first)\r\n"
                + "\(String(second.utf8.count, radix: 16))\r\n\(second)\r\n0\r\n\r\n"
            : "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let context { try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)) }
                    try channel.pipeline.syncOperations.addHandler(FixedHTTPResponder(response: response))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return (channel, try #require(channel.localAddress?.port))
    }

    private func trustingTestCA() throws -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(TestCertificates.caPEM.utf8), format: .pem)])
        return configuration
    }

    @Test(.timeLimit(.minutes(1)), arguments: [(false, false), (false, true), (true, false), (true, true)])
    func aPolicyIsFetched(tls: Bool, chunked: Bool) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let (channel, port) = try await serve(tls: tls, chunked: chunked, group: group)
        let fetcher = NIOMTASTSHTTPFetcher(group: group, timeout: 10, tlsConfiguration: try trustingTestCA(), allowPrivateAddresses: true)
        let url = try #require(URL(string: "\(tls ? "https" : "http")://127.0.0.1:\(port)/.well-known/mta-sts.txt"))
        let response = try await fetcher.fetch(url: url)
        try await channel.close()
        try await group.shutdownGracefully()
        #expect(response.statusCode == 200)
        #expect(response.contentType?.hasPrefix("text/plain") == true)
        #expect(String(decoding: response.body, as: UTF8.self) == Self.policy)
    }

    private struct FixedResolver: MTASTSAddressResolving {
        let addresses: [DNSAddress]
        func resolveAddresses(hostname: String) async throws -> [DNSAddress] { addresses }
    }

    /// Release review: NIOSSL accepts an IP SAN equal to the dialed address
    /// even when a host name was asked for, so an IP-only certificate passed
    /// for the policy host. A name now needs a matching DNS SAN.
    @Test(.timeLimit(.minutes(1)))
    func aPolicyHostNameNeedsADNSNameInTheCertificate() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }
        let loopback = FixedResolver(addresses: [.v4([127, 0, 0, 1])])
        for (leaf, host, accepted) in [(STARTTLSCertificateTests.Leaf.ipOnly, "mta-sts.victim.test", false),
                                       (.named, "mx.victim.test", true), (.dnsOnly, "other.victim.test", false)] {
            let (channel, port) = try await serve(leaf: leaf, group: group)
            let fetcher = NIOMTASTSHTTPFetcher(
                group: group, timeout: 10, tlsConfiguration: try trustingTestCA(),
                addressResolver: loopback, allowPrivateAddresses: true
            )
            let url = try #require(URL(string: "https://\(host):\(port)/.well-known/mta-sts.txt"))
            do {
                let response = try await fetcher.fetch(url: url)
                #expect(accepted && response.statusCode == 200, "\(leaf) for \(host) was accepted")
            } catch {
                #expect(!accepted, "\(leaf) for \(host): \(error)")
                if leaf == .ipOnly { #expect(error as? CertificateNameError == .noDNSName(host: host)) }
            }
            try await channel.close()
        }
    }

    /// Release review (SSRF): the host is resolved once and only globally
    /// routable addresses are dialed, by default.
    @Test(.timeLimit(.minutes(1)))
    func privateAddressesAreNeverDialedByDefault() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }
        let (channel, port) = try await serve(tls: false, chunked: false, group: group)
        for (resolver, url) in [
            (FixedResolver(addresses: [.v4([127, 0, 0, 1]), .v4([10, 0, 0, 1]), .v6(Array(repeating: 0, count: 15) + [1])]), "http://mta-sts.victim.test:\(port)/"),
            (FixedResolver(addresses: []), "http://127.0.0.1:\(port)/"),
            (FixedResolver(addresses: []), "http://[::1]:\(port)/"),
        ] {
            let fetcher = NIOMTASTSHTTPFetcher(group: group, timeout: 10, addressResolver: resolver)
            await #expect(throws: MTASTSHTTPFetchError.self) { _ = try await fetcher.fetch(url: try #require(URL(string: url))) }
        }
        // The default resolver path, too: a private literal is refused.
        await #expect(throws: MTASTSHTTPFetchError.noPermittedAddress(host: "127.0.0.1")) {
            _ = try await NIOMTASTSHTTPFetcher(group: group, timeout: 10).fetch(url: try #require(URL(string: "http://127.0.0.1:\(port)/")))
        }
        try await channel.close()
    }

    @Test func anIPv6HostIsBracketedInTheHostHeader() {
        #expect(NIOMTASTSHTTPFetcher.addressLiteral("::1") == .v6(Array(repeating: 0, count: 15) + [1]))
        #expect(NIOMTASTSHTTPFetcher.addressLiteral("192.0.2.1") == .v4([192, 0, 2, 1]))
        #expect(NIOMTASTSHTTPFetcher.addressLiteral("mta-sts.example.com") == nil)
    }

    @Test(.timeLimit(.minutes(1)))
    func anUntrustedCertificateFailsTheFetch() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let (channel, port) = try await serve(tls: true, chunked: false, group: group)
        let fetcher = NIOMTASTSHTTPFetcher(group: group, timeout: 10, allowPrivateAddresses: true) // system trust store
        let url = try #require(URL(string: "https://127.0.0.1:\(port)/.well-known/mta-sts.txt"))
        await #expect(throws: (any Error).self) { _ = try await fetcher.fetch(url: url) }
        try await channel.close()
        try await group.shutdownGracefully()
    }
}

private final class FixedHTTPResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let response: String
    private var answered = false
    init(response: String) { self.response = response }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !answered else { return }
        answered = true
        let channel = context.channel
        context.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(string: response))).whenComplete { _ in channel.close(promise: nil) }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) { context.close(promise: nil) }
}

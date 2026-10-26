//
//  MTASTSHTTPFetcherTLSShutdownTests.swift
//  PerfectSMTPTests
//
//  6.0.1: closing a NIOSSL channel starts a clean TLS shutdown that keeps
//  reading, and discarding, until the peer's close_notify or NIOSSL's
//  `shutdownTimeout` (5 s by default). A policy host that streams an
//  endless body and never answers the client's close_notify kept every
//  capped (or timed-out, or refused) fetch's connection reading at full
//  speed for 5 s: 50 capped fetches on macOS took 19-25 s and moved
//  52-60 GB. The fetcher now stops reading and closes after 1 ms.
//
//  The second half pins down that this never lets a cut-off response
//  through: a short Content-Length body, an unterminated chunked body, or
//  a close-delimited body without the server's close_notify is refused.
//  Runs against local TLS servers on 127.0.0.1.
//

import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import Testing
@testable import PerfectSMTP

@Suite(.serialized)
struct MTASTSHTTPFetcherTLSShutdownTests {
    // MARK: - The connection is let go at once

    /// The server ignores the client's close_notify and keeps pumping. The
    /// connection must be gone well before NIOSSL's 5 s default.
    @Test(.timeLimit(.minutes(1)), arguments: [Framing.closeDelimited, .contentLength(1_000_000_000_000), .chunked])
    func aCappedFetchLetsGoOfADeafEndlessServerAtOnce(framing: Framing) async throws {
        let server = try await ScriptedTLSServer.start(.init(framing: framing, body: .endless, deafAfter: .request))
        let returned = try await server.expectFetch(throws: MTASTSHTTPFetchError.responseTooLarge(limit: MTASTSPolicyManager.maximumPolicyResponseSizeBytes))
        try await server.expectClosedSoon(after: returned)
        try await server.stop()
    }

    @Test(.timeLimit(.minutes(1)))
    func aTimedOutFetchLetsGoOfADeafServerAtOnce() async throws {
        // Headers and a little body, then silence: the fetch runs into its
        // own deadline.
        let server = try await ScriptedTLSServer.start(.init(framing: .contentLength(1000), body: .bytes(10), deafAfter: .request))
        let returned = try await server.expectFetch(throws: MTASTSHTTPFetchError.timedOut, timeout: 0.5)
        try await server.expectClosedSoon(after: returned)
        try await server.stop()
    }

    @Test(.timeLimit(.minutes(1)))
    func aRefusedCertificateLetsGoOfADeafServerAtOnce() async throws {
        // An IP-only certificate for a host name: refused after the handshake.
        let server = try await ScriptedTLSServer.start(.init(leaf: .ipOnly, framing: .closeDelimited, body: .endless, deafAfter: .handshake))
        let returned = try await server.expectFetch(throws: CertificateNameError.noDNSName(host: "mta-sts.victim.test"), host: "mta-sts.victim.test")
        try await server.expectClosedSoon(after: returned)
        try await server.stop()
    }

    // MARK: - A cut-off response is never accepted

    @Test(.timeLimit(.minutes(1)), arguments: [ScriptedTLSServer.Ending.closeNotify, .tcpCloseWithoutCloseNotify])
    func aShortContentLengthBodyIsRefused(ending: ScriptedTLSServer.Ending) async throws {
        let server = try await ScriptedTLSServer.start(.init(framing: .contentLength(Self.policy.utf8.count + 10), body: .policy, ending: ending))
        try await server.expectNoResponse(ending)
        try await server.stop()
    }

    @Test(.timeLimit(.minutes(1)), arguments: [ScriptedTLSServer.Ending.closeNotify, .tcpCloseWithoutCloseNotify])
    func anUnterminatedChunkedBodyIsRefused(ending: ScriptedTLSServer.Ending) async throws {
        let server = try await ScriptedTLSServer.start(.init(framing: .chunked, body: .policy, ending: ending))
        try await server.expectNoResponse(ending)
        try await server.stop()
    }

    /// A body delimited by the close is complete only if the close is the
    /// server's: an attacker on the path can end the TCP stream, but can't
    /// forge close_notify.
    @Test(.timeLimit(.minutes(1)))
    func aCloseDelimitedBodyWithoutCloseNotifyIsRefused() async throws {
        let server = try await ScriptedTLSServer.start(.init(framing: .closeDelimited, body: .policy, ending: .tcpCloseWithoutCloseNotify))
        try await server.expectNoResponse(.tcpCloseWithoutCloseNotify)
        try await server.stop()
    }

    @Test(.timeLimit(.minutes(1)))
    func aCloseDelimitedBodyEndedByCloseNotifyIsAccepted() async throws {
        let server = try await ScriptedTLSServer.start(.init(framing: .closeDelimited, body: .policy, ending: .closeNotify))
        let response = try await server.fetcher().fetch(url: server.url())
        try await server.stop()
        #expect(response.statusCode == 200)
        #expect(String(decoding: response.body, as: UTF8.self) == Self.policy)
    }

    static let policy = "version: STSv1\r\nmode: enforce\r\nmx: mx.victim.test\r\nmax_age: 86400\r\n"

    enum Framing: Sendable, CustomTestStringConvertible {
        case closeDelimited, contentLength(Int), chunked
        var testDescription: String {
            switch self {
            case .closeDelimited: "close-delimited"
            case .contentLength: "Content-Length"
            case .chunked: "chunked"
            }
        }
    }
}

/// A TLS server on its own thread (an endless pump on the client's loop
/// would compete with the client) that answers the first request by
/// script and records when the connection closed.
final class ScriptedTLSServer: Sendable {
    enum Body: Sendable { case policy, bytes(Int), endless }
    enum DeafPoint: Sendable { case handshake, request }
    enum Ending: Sendable { case closeNotify, tcpCloseWithoutCloseNotify }

    struct Script: Sendable {
        var leaf: STARTTLSCertificateTests.Leaf = .named
        var framing: MTASTSHTTPFetcherTLSShutdownTests.Framing
        var body: Body
        /// From then on the server reads nothing, so it never sees (or
        /// answers) the client's close_notify.
        var deafAfter: DeafPoint? = nil
        /// How the server ends after writing a finite body; nil leaves it open.
        var ending: Ending? = nil
    }

    private let group: MultiThreadedEventLoopGroup
    private let channel: any Channel
    private let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let closedAt: NIOLockedValueBox<Date?>

    private init(group: MultiThreadedEventLoopGroup, channel: any Channel, closedAt: NIOLockedValueBox<Date?>) {
        self.group = group
        self.channel = channel
        self.closedAt = closedAt
    }

    static func start(_ script: Script) async throws -> ScriptedTLSServer {
        let (certPEM, keyPEM): (String, String)
        switch script.leaf {
        case .ipOnly: (certPEM, keyPEM) = (TestCertificates.ipOnlyCertificatePEM, TestCertificates.ipOnlyKeyPEM)
        case .named: (certPEM, keyPEM) = (TestCertificates.namedCertificatePEM, TestCertificates.namedKeyPEM)
        case .dnsOnly: (certPEM, keyPEM) = (TestCertificates.dnsOnlyCertificatePEM, TestCertificates.dnsOnlyKeyPEM)
        }
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: Array(certPEM.utf8), format: .pem))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem))
        )
        // The server's own clean close (`.closeNotify`) needn't linger.
        configuration.shutdownTimeout = .milliseconds(100)
        let context = try NIOSSLContext(configuration: configuration)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let closedAt = NIOLockedValueBox<Date?>(nil)
        let channel = try await ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(SocketEnd(closedAt: closedAt))
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    try channel.pipeline.syncOperations.addHandler(ScriptedResponder(script: script))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return ScriptedTLSServer(group: group, channel: channel, closedAt: closedAt)
    }

    func url(host: String = "127.0.0.1") throws -> URL {
        try #require(URL(string: "https://\(host):\(channel.localAddress?.port ?? 0)/.well-known/mta-sts.txt"))
    }

    func fetcher(timeout: TimeInterval = 10) throws -> NIOMTASTSHTTPFetcher {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(TestCertificates.caPEM.utf8), format: .pem)])
        return NIOMTASTSHTTPFetcher(
            group: clientGroup, timeout: timeout, tlsConfiguration: configuration,
            addressResolver: LoopbackResolver(), allowPrivateAddresses: true
        )
    }

    /// Fetches, expects `expected`, and returns when the fetch returned.
    func expectFetch<E: Error & Equatable>(throws expected: E, timeout: TimeInterval = 10, host: String = "127.0.0.1") async throws -> Date {
        let fetcher = try fetcher(timeout: timeout)
        let url = try url(host: host)
        await #expect(throws: expected) { _ = try await fetcher.fetch(url: url) }
        return Date()
    }

    /// A cut-off response must fail the fetch, for the reason the ending
    /// gives: the HTTP framing is incomplete at the server's close_notify,
    /// or the TCP stream ended without one.
    func expectNoResponse(_ ending: Ending) async throws {
        let fetcher = try fetcher()
        let url = try url()
        do {
            let response = try await fetcher.fetch(url: url)
            Issue.record("a cut-off response was accepted: status \(response.statusCode), \(response.body.count) body bytes")
        } catch {
            switch ending {
            case .closeNotify: #expect(error as? HTTPParserError == .invalidEOFState, "\(error)")
            case .tcpCloseWithoutCloseNotify: #expect(error as? NIOSSLError == .uncleanShutdown, "\(error)")
            }
        }
    }

    /// The server sees the connection close well before NIOSSL's 5 s
    /// default shutdown timeout (2 s leaves room for an emulated machine).
    func expectClosedSoon(after returned: Date) async throws {
        let deadline = Date().addingTimeInterval(10)
        while closedAt.withLockedValue({ $0 }) == nil, Date() < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let closed = try #require(closedAt.withLockedValue { $0 }, "the client never closed the connection")
        #expect(closed.timeIntervalSince(returned) < 2, "the connection stayed open \(closed.timeIntervalSince(returned)) s after the fetch returned")
    }

    func stop() async throws {
        try await channel.close()
        try await group.shutdownGracefully()
        try await clientGroup.shutdownGracefully()
    }
}

private struct LoopbackResolver: MTASTSAddressResolving {
    func resolveAddresses(hostname: String) async throws -> [DNSAddress] { [.v4([127, 0, 0, 1])] }
}

/// Socket side of the server's TLS handler: records the close, can go
/// deaf (drop everything inbound), and can close the TCP connection
/// without NIOSSL sending close_notify. Event-loop confined.
private final class SocketEnd: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let closedAt: NIOLockedValueBox<Date?>
    var deaf = false

    init(closedAt: NIOLockedValueBox<Date?>) { self.closedAt = closedAt }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !deaf { context.fireChannelRead(data) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        closedAt.withLockedValue { $0 = $0 ?? Date() }
        context.fireChannelInactive()
    }
}

/// Answers the first request by script. Event-loop confined.
private final class ScriptedResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let script: ScriptedTLSServer.Script
    private var started = false
    private let filler = ByteBuffer(repeating: UInt8(ascii: "#"), count: 16 * 1024)

    init(script: ScriptedTLSServer.Script) { self.script = script }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case .handshakeCompleted? = event as? TLSUserEvent, script.deafAfter == .handshake { goDeaf(context) }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !started else { return }
        started = true
        if script.deafAfter == .request { goDeaf(context) }
        var head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
        switch script.framing {
        case .closeDelimited: break
        case .contentLength(let length): head += "Content-Length: \(length)\r\n"
        case .chunked: head += "Transfer-Encoding: chunked\r\n"
        }
        var out = ByteBuffer(string: head + "\r\n")
        switch script.body {
        case .policy: out.writeImmutableBuffer(encoded(ByteBuffer(string: MTASTSHTTPFetcherTLSShutdownTests.policy)))
        case .bytes(let count): out.writeImmutableBuffer(encoded(ByteBuffer(repeating: UInt8(ascii: "#"), count: count)))
        case .endless: break
        }
        let channel = context.channel
        let ending = script.ending
        // Closing from SocketEnd's context goes straight to the socket, past NIOSSL.
        let socketEnd = NIOLoopBound(try? context.pipeline.syncOperations.context(handlerType: SocketEnd.self), eventLoop: context.eventLoop)
        context.writeAndFlush(Self.wrapOutboundOut(out)).whenComplete { _ in
            switch ending {
            case .closeNotify?: channel.close(promise: nil)
            case .tcpCloseWithoutCloseNotify?: socketEnd.value?.close(promise: nil)
            case nil: break
            }
        }
        if case .endless = script.body { pump(context) }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if started, case .endless = script.body { pump(context) }
        context.fireChannelWritabilityChanged()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) { context.close(promise: nil) }

    private func pump(_ context: ChannelHandlerContext) {
        while context.channel.isActive, context.channel.isWritable {
            context.writeAndFlush(Self.wrapOutboundOut(encoded(filler)), promise: nil)
        }
    }

    private func encoded(_ bytes: ByteBuffer) -> ByteBuffer {
        guard case .chunked = script.framing else { return bytes }
        var chunk = ByteBuffer(string: String(bytes.readableBytes, radix: 16) + "\r\n")
        chunk.writeImmutableBuffer(bytes)
        chunk.writeString("\r\n")
        return chunk
    }

    private func goDeaf(_ context: ChannelHandlerContext) {
        try? context.pipeline.syncOperations.handler(type: SocketEnd.self).deaf = true
    }
}

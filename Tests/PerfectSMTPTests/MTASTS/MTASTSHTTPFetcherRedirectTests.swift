//
//  MTASTSHTTPFetcherRedirectTests.swift
//  PerfectSMTPTests
//
//  FIX #3 (MEDIUM security, milestone security review): `URLSessionMTASTSFetcher`
//  must never follow an HTTP redirect -- RFC 8461 §3.3 explicitly says
//  "HTTP 3xx redirects MUST NOT be followed" (fetched and verified directly
//  against the published RFC text), and a malicious policy server able to
//  redirect this fetch to an arbitrary host/scheme is a real request-
//  forgery primitive even though the fetched body is only ever used for
//  MTA-STS text parsing, never reflected back to anyone.
//
//  This test drives the *real* `URLSessionMTASTSFetcher` (not the
//  `MTASTSHTTPFetching` protocol fake `FakeMTASTSHTTPFetcher` other MTA-STS
//  tests use) against a real local HTTP server over a real socket -- the
//  redirect-refusal mechanism (`RedirectRefusingTaskDelegate`) lives
//  entirely inside `URLSession`'s own redirect callback, which a protocol-
//  level fake bypasses entirely and so cannot exercise.
//

import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct MTASTSHTTPFetcherRedirectTests {
    @Test(arguments: FetcherKind.allCases)
    func aRedirectResponseIsTreatedAsAFetchFailureNotSilentlyFollowed(kind: FetcherKind) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let requestCount = RequestCounter()
        let server = try await RedirectingFakeHTTPServer.start(group: group, onRequest: { await requestCount.increment() })

        let fetcher = kind.make()
        let url = URL(string: "http://127.0.0.1:\(server.port)/.well-known/mta-sts.txt")!

        let response = try await fetcher.fetch(url: url)

        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(response.statusCode == 301, "expected the redirect (3xx) response itself to be returned, not a followed 200 -- got \(response.statusCode)")
        #expect(
            await requestCount.value == 1,
            "the fetcher must never have followed the redirect and issued a second request against the redirect target -- any count above 1 means the redirect was actually followed"
        )
    }

}

private actor RequestCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}

private enum RedirectingFakeHTTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup, onRequest: @escaping @Sendable () async -> Void) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(RedirectingHTTPHandler(onRequest: onRequest))
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private enum FakeServerError: Error {
    case noLocalPort
}

/// Responds to every complete HTTP/1.1 request (detected by the header-
/// terminating blank line) with a fixed `301 Moved Permanently` pointing
/// back at this same server's `/should-never-be-fetched` path -- if the
/// client actually followed it, this handler would see (and count, via
/// `onRequest`) a second request.
private final class RedirectingHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private let onRequest: @Sendable () async -> Void

    init(onRequest: @escaping @Sendable () async -> Void) {
        self.onRequest = onRequest
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        guard containsHeaderTerminator(accumulated) else { return }
        accumulated.moveReaderIndex(forwardBy: accumulated.readableBytes)

        let callback = onRequest
        Task { await callback() }

        let port = context.channel.localAddress?.port ?? 0
        let body = ""
        let response =
            "HTTP/1.1 301 Moved Permanently\r\n"
            + "Location: http://127.0.0.1:\(port)/should-never-be-fetched\r\n"
            + "Content-Type: text/plain\r\n"
            + "Content-Length: \(body.utf8.count)\r\n"
            + "Connection: close\r\n"
            + "\r\n"
            + body
        var buffer = context.channel.allocator.buffer(capacity: response.utf8.count)
        buffer.writeString(response)
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        context.close(promise: nil)
    }

    private func containsHeaderTerminator(_ buffer: ByteBuffer) -> Bool {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        let bytes = Array(buffer.readableBytesView)
        guard bytes.count >= terminator.count else { return false }
        for start in 0...(bytes.count - terminator.count) {
            if Array(bytes[start..<(start + terminator.count)]) == terminator { return true }
        }
        return false
    }
}

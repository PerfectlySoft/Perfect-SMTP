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
import Testing
@testable import PerfectSMTP

struct MTASTSHTTPFetcherSizeLimitTests {
    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func anEndlessBodyIsCutOffAtTheCapWithoutBufferingIt(declareHugeLength: Bool) async throws {
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

        let fetcher = URLSessionMTASTSFetcher(timeout: 30)
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
        #if !canImport(FoundationNetworking)
        #expect(total < 256 * 1024 * 1024, "the server streamed \(total) bytes before the client stopped reading")
        #endif
        // On Linux, corelibs Foundation can keep draining the socket for a
        // moment after the task is cancelled (once 2.4 GB over loopback in
        // a loaded full-suite run). The bytes are dropped, not buffered: a
        // standalone probe under CPU load kept max RSS at about 60 MB over
        // ten endless-body fetches. So only the hang-up is asserted there.
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

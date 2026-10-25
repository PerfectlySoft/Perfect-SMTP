//
//  MTASTSHTTPFetcherTimeoutTests.swift
//  PerfectSMTPTests
//
//  `URLSessionMTASTSFetcher`'s `timeout` bounds the whole fetch. A policy
//  host that sends its headers and then trickles the body one byte at a
//  time never trips `URLSession`'s between-bytes request timeout, so only
//  the fetcher's own deadline ends the fetch. Runs against a local server
//  on 127.0.0.1.
//

import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct MTASTSHTTPFetcherTimeoutTests {
    @Test(.timeLimit(.minutes(1)), arguments: FetcherKind.allCases)
    func aTricklingPolicyHostIsCutOffAtTheFetchersDeadline(kind: FetcherKind) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(TricklingHTTPHandler())
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        let port = try #require(channel.localAddress?.port)

        let fetcher = kind.make(timeout: 1)
        let url = try #require(URL(string: "http://127.0.0.1:\(port)/.well-known/mta-sts.txt"))
        let started = Date()
        await #expect(throws: MTASTSHTTPFetchError.timedOut) {
            _ = try await fetcher.fetch(url: url)
        }
        let elapsed = Date().timeIntervalSince(started)

        try await channel.close()
        try await group.shutdownGracefully()
        #expect(elapsed < 10, "the fetch should end at its 1 s deadline, took \(elapsed) s")
    }
}

/// Answers any request with a 200 whose 60 kB body (under the 64 KiB cap) arrives one byte every
/// 100 ms, so bytes never stop for long enough to trip an idle timeout.
private final class TricklingHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    // Event-loop confined: every callback, and the repeated task, runs on
    // the child channel's loop.
    private var started = false
    private var task: RepeatedTask?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !started else { return }
        started = true
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 60000\r\n\r\n"
        context.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(string: head)), promise: nil)
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        task = context.eventLoop.scheduleRepeatedTask(initialDelay: .milliseconds(100), delay: .milliseconds(100)) { _ in
            bound.value.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(string: "x")), promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        task?.cancel()
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        task?.cancel()
    }
}

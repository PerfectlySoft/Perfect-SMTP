//
//  SMTPConnectionTeardownTests.swift
//  PerfectSMTPTests
//
//  `NIOAsyncChannel(wrappingChannelSynchronously:)` builds its outbound
//  `NIOAsyncWriter` with `finishOnDeinit: false`, so the writer traps with
//  "Deinited NIOAsyncWriter without calling finish()" if its last reference
//  goes away while the writer is unfinished. NIO finishes it for us when
//  the channel goes inactive (the handler's `channelInactive` finishes the
//  sink), so the only dangerous window is dropping an `SMTPConnection`
//  while its channel is still open.
//
//  In production that window is closed by a NIO detail rather than by our
//  code: `SMTPBootstrap` wraps the channel *after* it is already active, so
//  `NIOAsyncChannelHandler` never sees `channelActive` and keeps its own
//  copy of the writer until `handlerRemoved`, which runs after the sink is
//  finished. The real-socket tests below exercise every teardown path
//  (pool close-then-drop, unhealthy release, shutdown with idle
//  connections, and dropping a connection without closing it at all).
//  They passed without `SMTPConnection.deinit`'s `finish()` on macOS and
//  Linux, which is the evidence for the claim above; with the `deinit` in
//  place they are smoke tests and can no longer detect a change in that
//  NIO detail.
//
//  A channel that becomes active *after* wrapping (as an
//  `NIOAsyncTestingChannel` does when a test calls `connect(to:)`) has the
//  handler drop its copy, leaving `SMTPConnection` the only owner -- that
//  is the path that used to trap, and `SMTPConnection.deinit` now finishes
//  the writer so it no longer depends on who else holds a reference.
//

import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import PerfectSMTP

struct SMTPConnectionTeardownTests {

    // MARK: - Regression: last owner dropped while the channel is open

    @Test func droppingAConnectionWhoseChannelActivatedAfterWrappingDoesNotTrap() async throws {
        // Before `SMTPConnection.deinit` finished the writer, this test
        // crashed the process with "Deinited NIOAsyncWriter without
        // calling finish()".
        var channels: [NIOAsyncTestingChannel] = []
        for _ in 0..<20 {
            weak var released: SMTPConnection?
            do {
                let (connection, channel) = try await ConnectionHarness.make()
                try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
                #expect(connection.channel.isActive)
                channels.append(channel)
                released = connection
                // `connection` is released here with its channel still open.
            }
            #expect(released == nil, "the connection must actually deinit for this test to mean anything")
        }
        for channel in channels {
            #expect(channel.isActive)
            _ = try? await channel.finish()
        }
    }

    // MARK: - Real sockets

    @Test func droppingADialedConnectionWithoutClosingItDoesNotTrap() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let server = try await TeardownFakeServer.start(group: group)
        var channels: [Channel] = []
        for _ in 0..<50 {
            let connection = try await Self.dial(port: server.port, group: group)
            channels.append(connection.channel)
        }
        for channel in channels {
            #expect(channel.isActive)
            try? await channel.close()
        }
        try await server.channel.close()
        try await group.shutdownGracefully()
    }

    @Test func closeThenImmediatelyDropDoesNotTrap() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let server = try await TeardownFakeServer.start(group: group)
        var closeFutures: [EventLoopFuture<Void>] = []
        for _ in 0..<200 {
            let connection = try await Self.dial(port: server.port, group: group)
            // Exactly what `SMTPConnectionPool.release` does: fire-and-forget
            // close from off the event loop, then drop the connection.
            closeFutures.append(connection.channel.closeFuture)
            connection.channel.close(promise: nil)
        }
        for future in closeFutures { try? await future.get() }
        try await server.channel.close()
        try await group.shutdownGracefully()
    }

    @Test func poolUnhealthyReleaseAndShutdownWithIdleConnectionsDoNotTrap() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let server = try await TeardownFakeServer.start(group: group)
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 8, circuitBreakerThreshold: 1_000_000),
            ehloHostname: "client.example.com",
            group: group
        )
        let key = SMTPConnectionPool.Key(host: "127.0.0.1", port: server.port, tls: .none)
        let completed = try await withThrowingTaskGroup(of: Bool.self) { tasks in
            for i in 0..<200 {
                tasks.addTask {
                    // Every third checkout is released unhealthy (closed and
                    // dropped by the pool); the rest go back to idle.
                    (try? await pool.withConnection(to: key, isHealthy: { $0 }) { _ in i % 3 != 0 }) != nil
                }
            }
            return try await tasks.reduce(0) { $0 + ($1 ? 1 : 0) }
        }
        #expect(completed == 200)
        await pool.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()
    }

    private static func dial(port: Int, group: any EventLoopGroup) async throws -> SMTPConnection {
        let asyncChannel = try await SMTPBootstrap.connect(host: "127.0.0.1", port: port, tls: .none, group: group)
        let connection = SMTPConnection(asyncChannel: asyncChannel, ehloHostname: "client.example.com")
        try await connection.negotiateCapabilities()
        return connection
    }
}

private enum TeardownFakeServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    struct NoLocalPort: Error {}

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(TeardownFakeServerHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw NoLocalPort() }
        return Running(channel: channel, port: port)
    }
}

/// Plaintext fake server: a greeting, an EHLO reply with no extensions
/// worth negotiating, and `250` for everything else.
private final class TeardownFakeServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let lfIndex = accumulated.readableBytesView.firstIndex(of: 0x0A) {
            let line = accumulated.readString(length: lfIndex - accumulated.readerIndex) ?? ""
            accumulated.moveReaderIndex(forwardBy: 1)
            if line.uppercased().hasPrefix("EHLO") {
                writeLine(context: context, "250-fake.example Hello")
                writeLine(context: context, "250 8BITMIME")
            } else {
                writeLine(context: context, "250 OK")
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

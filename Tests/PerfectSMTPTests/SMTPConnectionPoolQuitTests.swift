//
//  SMTPConnectionPoolQuitTests.swift
//  PerfectSMTPTests
//
//  Release review nit: retiring an idle connection sends a best-effort
//  QUIT before closing, instead of just dropping the socket.
//

import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct SMTPConnectionPoolQuitTests {
    @Test func shutdownSendsQUITToIdleConnections() async throws {
        let channels = NIOLockedValueBox<[NIOAsyncTestingChannel]>([])
        let pool = SMTPConnectionPool(configuration: .init(maxPerHost: 1), group: NIOAsyncTestingEventLoop()) { _ in
            let (connection, channel) = try await ConnectionHarness.make()
            try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
            channels.withLockedValue { $0.append(channel) }
            return connection
        }
        let key = SMTPConnectionPool.Key(host: "relay.example", port: 25, tls: .none)
        try await pool.withConnection(to: key) { _ in () } // dialed, then idle
        await pool.shutdown()

        let channel = try #require(channels.withLockedValue { $0.first })
        try await channel.closeFuture.get()
        var written = try #require(try await channel.readOutbound(as: ByteBuffer.self))
        #expect(written.readString(length: written.readableBytes) == "QUIT\r\n")
    }
}

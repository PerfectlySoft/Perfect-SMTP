//
//  SMTPConnectionPoolQuitTests.swift
//  PerfectSMTPTests
//
//  Release review nit: retiring an idle connection sends a best-effort
//  QUIT before closing, instead of just dropping the socket.
//

import NIOConcurrencyHelpers
import Foundation
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

struct QuitWaitsFor221Tests {
    @Test func quitWaitsForThe221ThenCloses() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
        let started = DispatchTime.now()
        let quit = Task { await connection.quitAndClose(timeout: 5) }
        #expect(try await expectClientLine(channel) == "QUIT")
        #expect(channel.isActive, "closed before the 221")
        try await serverSend(channel, "221 2.0.0 Bye")
        await quit.value
        try await channel.closeFuture.get()
        let seconds = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1e9
        #expect(seconds < 4, "closed \(seconds) s after QUIT; it should follow the 221, not the timeout")
    }

    @Test func quitClosesAtTheDeadlineWithoutA221() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
        await connection.quitAndClose(timeout: 0.2)
        try await channel.closeFuture.get()
    }
}

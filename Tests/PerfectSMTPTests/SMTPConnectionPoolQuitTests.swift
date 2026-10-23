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

/// Re-review: an eviction used to wait up to 0.5 s for the 221 before the
/// close freed the slot, delaying the checkout waiting for it.
struct EvictionDoesNotWaitForTheQUITReplyTests {
    @Test(.timeLimit(.minutes(1)))
    func aCheckoutWaitingOnAnEvictionIsNotHeldUpByASilentServer() async throws {
        // The server never answers QUIT (answersQUIT: false), and the QUIT
        // reply timeout is 30 s: had the eviction waited for a 221, the
        // checkout would take 30 s. Robust on slow machines, unlike a tight
        // bound against the 0.5 s default.
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 1, maxTotal: 1, quitReplyTimeout: 30), group: NIOAsyncTestingEventLoop()
        ) { _ in
            let (connection, channel) = try await ConnectionHarness.make()
            try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
            return connection
        }
        let hostA = SMTPConnectionPool.Key(host: "a.example.com", port: 25, tls: .none)
        let hostB = SMTPConnectionPool.Key(host: "b.example.com", port: 25, tls: .none)
        try await pool.withConnection(to: hostA) { _ in () } // A is now idle and holds the only slot
        let started = DispatchTime.now()
        try await pool.withConnection(to: hostB) { _ in () } // evicts A
        let seconds = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1e9
        await pool.shutdown()
        #expect(seconds < 10, "the checkout waited \(seconds) s for the evicted connection's QUIT reply")
    }
}

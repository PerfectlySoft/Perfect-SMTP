//
//  SMTPBootstrapTimeoutTests.swift
//  PerfectSMTPTests
//
//  Real-socket regressions for `SMTPBootstrap.connect` hanging forever.
//  `SMTPBootstrapHandler` used to have no `channelInactive` handling and no
//  timer, so a peer that accepted TCP and then hung up before (or during)
//  the bootstrap exchange, or that never spoke at all, left `readyPromise`
//  uncompleted. In `SMTPConnectionPool` such a dial kept its reserved slot
//  forever.
//
//  Same shape as `STARTTLSRealSocketTests`: `connect` runs on an
//  unstructured `Task` the test never awaits, and the test polls for its
//  outcome with a bounded budget, because a stuck real-socket future isn't
//  interrupted by cancellation. `.timeLimit` is only a backstop. If the
//  attempt is still pending when the budget runs out, the client event loop
//  group is deliberately left running (shutting it down would leak the
//  pending promise and trip NIO's debug assertion instead of reporting a
//  clean failure).
//

import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP
@testable import PerfectSMTPCore

struct SMTPBootstrapTimeoutTests {

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatClosesBeforeTheGreetingFailsTheConnectPromptly() async throws {
        let error = try await connectExpectingFailure(behavior: .closeOnAccept, tls: .none, replyTimeout: 300)
        #expect(Self.isConnectionFailed(error, because: .channelClosedByPeer), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aSilentPeerFailsTheConnectWhenTheReplyTimeoutElapses() async throws {
        let error = try await connectExpectingFailure(behavior: .silent, tls: .none, replyTimeout: 0.5)
        #expect(Self.isConnectionFailed(error, because: .replyTimedOut), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aSilentPeerUnderImplicitTLSFailsTheConnectWhenTheReplyTimeoutElapses() async throws {
        // The client sends a ClientHello the server never answers.
        let error = try await connectExpectingFailure(behavior: .silent, tls: .implicit, replyTimeout: 0.5)
        #expect(Self.isConnectionFailed(error, because: .replyTimedOut), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aRejectingGreetingFollowedByACloseStillReportsTheRejection() async throws {
        // The close must not mask the 554 the decoder delivers first.
        let error = try await connectExpectingFailure(behavior: .rejectThenClose, tls: .none, replyTimeout: 300)
        guard case SMTPError.permanentFailure(let reply)? = error else {
            Issue.record("expected .permanentFailure, got \(String(describing: error))")
            return
        }
        #expect(reply.code == 554)
    }

    // MARK: - STARTTLS steps

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatNeverAnswersTheProbeEHLOFailsTheConnectWhenTheReplyTimeoutElapses() async throws {
        let error = try await connectExpectingFailure(behavior: .greetThenSilent, tls: .startTLS, replyTimeout: 0.5)
        #expect(Self.isConnectionFailed(error, because: .replyTimedOut), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatClosesInsteadOfAnsweringTheProbeEHLOFailsTheConnect() async throws {
        let error = try await connectExpectingFailure(behavior: .greetThenCloseOnEHLO, tls: .startTLS, replyTimeout: 300)
        #expect(Self.isConnectionFailed(error, because: .channelClosedByPeer), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatClosesInsteadOfAnsweringSTARTTLSFailsTheConnect() async throws {
        let error = try await connectExpectingFailure(behavior: .closeOnSTARTTLS, tls: .startTLS, replyTimeout: 300)
        #expect(Self.isConnectionFailed(error, because: .channelClosedByPeer), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatNeverAnswersSTARTTLSFailsTheConnectWhenTheReplyTimeoutElapses() async throws {
        let error = try await connectExpectingFailure(behavior: .silentOnSTARTTLS, tls: .startTLS, replyTimeout: 0.5)
        #expect(Self.isConnectionFailed(error, because: .replyTimedOut), "got \(String(describing: error))")
    }

    @Test(.timeLimit(.minutes(1)))
    func aPeerThatStallsTheSTARTTLSHandshakeFailsTheConnectWithoutAPlaintextFallbackSignal() async throws {
        // Inside the fenced upgrade window every failure is reported as
        // `.starttlsInjection`, which `DirectMXTransport` never answers with
        // a plaintext retry. A stalled handshake must keep that property.
        let error = try await connectExpectingFailure(behavior: .silentAfterSTARTTLSReady, tls: .startTLS, replyTimeout: 0.5)
        guard case SMTPError.starttlsInjection(let underlying)? = error else {
            Issue.record("expected .starttlsInjection, got \(String(describing: error))")
            return
        }
        #expect((underlying as? SMTPConnectionError) == .replyTimedOut)
    }

    // MARK: - Pool capacity

    @Test(.timeLimit(.minutes(1)))
    func aSilentPeerDoesNotPinThePoolsOnlySlot() async throws {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await BootstrapTestServer.start(behavior: .silent, group: serverGroup)
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 1, maxTotal: 1, replyTimeout: 0.5),
            group: clientGroup
        )
        let key = SMTPConnectionPool.Key(host: "127.0.0.1", port: server.port, tls: .none)

        // Two dials in a row through a one-slot pool: the second can only
        // start once the first has given its slot back.
        let outcome = OutcomeBox()
        Task {
            var failures = 0
            for _ in 0..<2 {
                do {
                    try await pool.withConnection(to: key) { _ in () }
                } catch {
                    failures += 1
                }
            }
            await outcome.set(failures)
        }
        let failures = await outcome.wait(seconds: 10) as? Int

        try? await server.channel.close()
        try? await serverGroup.shutdownGracefully()
        if failures != nil {
            await pool.shutdown()
            try? await clientGroup.shutdownGracefully()
        }
        #expect(failures == 2, "both dials should time out and release the slot; the pool is still stuck if this is nil")
    }

    // MARK: - Helpers

    private static func isConnectionFailed(_ error: (any Error)?, because expected: SMTPConnectionError) -> Bool {
        guard case SMTPError.connectionFailed(let underlying)? = error else { return false }
        return (underlying as? SMTPConnectionError) == expected
    }

    /// Runs `SMTPBootstrap.connect` against a fake server and returns the
    /// error it threw. Records an issue (and returns `nil`) if it succeeded
    /// or was still pending after the poll budget.
    private func connectExpectingFailure(
        behavior: BootstrapTestServer.Behavior,
        tls: TLSMode,
        replyTimeout: TimeInterval
    ) async throws -> (any Error)? {
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await BootstrapTestServer.start(behavior: behavior, group: serverGroup)

        let outcome = OutcomeBox()
        Task {
            do {
                let channel = try await SMTPBootstrap.connect(
                    host: "127.0.0.1", port: server.port, tls: tls,
                    replyTimeout: replyTimeout, group: clientGroup
                )
                try? await channel.channel.close()
                await outcome.set(ConnectOutcome.succeeded)
            } catch {
                await outcome.set(ConnectOutcome.failed(error))
            }
        }
        let result = await outcome.wait(seconds: 10) as? ConnectOutcome

        try? await server.channel.close()
        try? await serverGroup.shutdownGracefully()
        if result != nil {
            try? await clientGroup.shutdownGracefully()
        }

        switch result {
        case .failed(let error):
            return error
        case .succeeded:
            Issue.record("SMTPBootstrap.connect unexpectedly succeeded against \(behavior)")
            return nil
        case nil:
            Issue.record("SMTPBootstrap.connect was still pending after 10 s against \(behavior) (tls: \(tls))")
            return nil
        }
    }
}

private enum ConnectOutcome: Sendable {
    case succeeded
    case failed(any Error)
}

private actor OutcomeBox {
    private var value: (any Sendable)?

    func set(_ value: any Sendable) { self.value = value }

    /// Polls for up to `seconds`; `nil` if nothing was set in time.
    nonisolated func wait(seconds: Double) async -> (any Sendable)? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let value = await self.value { return value }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return await self.value
    }
}

/// A real-socket fake SMTP server that misbehaves in one specific way per
/// test. It never speaks TLS.
private enum BootstrapTestServer {
    enum Behavior: Sendable, CustomStringConvertible {
        /// Accepts, then closes before sending anything.
        case closeOnAccept
        /// Accepts and never sends a byte.
        case silent
        /// Sends `554` and closes at once.
        case rejectThenClose
        /// Greets, then never answers anything.
        case greetThenSilent
        /// Greets, then closes when the EHLO arrives.
        case greetThenCloseOnEHLO
        /// Greets, advertises STARTTLS, closes when STARTTLS arrives.
        case closeOnSTARTTLS
        /// Greets, advertises STARTTLS, never answers STARTTLS.
        case silentOnSTARTTLS
        /// Greets, advertises STARTTLS, says `220 Ready`, then ignores the
        /// ClientHello.
        case silentAfterSTARTTLSReady

        var description: String {
            switch self {
            case .closeOnAccept: "a peer that closes on accept"
            case .silent: "a silent peer"
            case .rejectThenClose: "a peer that sends 554 and closes"
            case .greetThenSilent: "a peer that never answers EHLO"
            case .greetThenCloseOnEHLO: "a peer that closes on EHLO"
            case .closeOnSTARTTLS: "a peer that closes on STARTTLS"
            case .silentOnSTARTTLS: "a peer that never answers STARTTLS"
            case .silentAfterSTARTTLSReady: "a peer that stalls the STARTTLS handshake"
            }
        }
    }

    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(behavior: Behavior, group: any EventLoopGroup) async throws -> Running {
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(Handler(behavior: behavior))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw StartError.noLocalPort }
        return Running(channel: channel, port: port)
    }

    enum StartError: Error { case noLocalPort }

    final class Handler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        typealias OutboundOut = ByteBuffer

        private let behavior: Behavior
        private var accumulated = ByteBuffer()
        private var tlsStarted = false

        init(behavior: Behavior) { self.behavior = behavior }

        func channelActive(context: ChannelHandlerContext) {
            switch behavior {
            case .closeOnAccept:
                context.close(promise: nil)
            case .silent:
                break
            case .rejectThenClose:
                writeLine(context: context, "554 no service")
                context.close(promise: nil)
            case .greetThenSilent:
                writeLine(context: context, "220 fake.example ESMTP")
                tlsStarted = true // ignore everything from here on
            case .greetThenCloseOnEHLO, .closeOnSTARTTLS, .silentOnSTARTTLS, .silentAfterSTARTTLSReady:
                writeLine(context: context, "220 fake.example ESMTP")
            }
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            guard !tlsStarted else { return } // swallow the ClientHello
            var incoming = Self.unwrapInboundIn(data)
            accumulated.writeBuffer(&incoming)
            while !tlsStarted, let line = extractLine() {
                handle(line: line.uppercased(), context: context)
            }
        }

        private func handle(line: String, context: ChannelHandlerContext) {
            if line.hasPrefix("EHLO") {
                if case .greetThenCloseOnEHLO = behavior {
                    context.close(promise: nil)
                    return
                }
                writeLine(context: context, "250-fake.example Hello")
                writeLine(context: context, "250 STARTTLS")
            } else if line == "STARTTLS" {
                switch behavior {
                case .closeOnSTARTTLS:
                    context.close(promise: nil)
                case .silentAfterSTARTTLSReady:
                    tlsStarted = true
                    writeLine(context: context, "220 Ready to start TLS")
                default:
                    break
                }
            }
        }

        private func extractLine() -> String? {
            guard let lfIndex = accumulated.readableBytesView.firstIndex(of: 0x0A) else { return nil }
            guard let bytes = accumulated.readBytes(length: lfIndex - accumulated.readerIndex) else { return nil }
            accumulated.moveReaderIndex(forwardBy: 1)
            var text = String(decoding: bytes, as: UTF8.self)
            if text.hasSuffix("\r") { text.removeLast() }
            return text
        }

        private func writeLine(context: ChannelHandlerContext, _ text: String) {
            var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
            buffer.writeString(text + "\r\n")
            context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        }
    }
}

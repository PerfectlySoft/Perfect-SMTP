//
//  TestHelpers.swift
//  PerfectSMTPTests
//

import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
@testable import PerfectSMTP

/// Builds the exact pre-bootstrap pipeline `SMTPBootstrap.connect`'s
/// `channelInitializer` builds (decoder, encoder, optional implicit-TLS
/// handler, `SMTPBootstrapHandler`), on a plain synchronous
/// `EmbeddedChannel` — for white-box, byte-buffer-precise tests of Phase
/// A's STARTTLS state machine that don't need a real socket or a real TLS
/// handshake.
enum BootstrapHarness {
    struct Built {
        let channel: EmbeddedChannel
        let decoder: SMTPResponseDecoder
        let promise: EventLoopPromise<NIOAsyncChannel<SMTPReply, SMTPCommand>>
    }

    static func make(tls: TLSMode, host: String = "smtp.example.com") throws -> Built {
        let channel = EmbeddedChannel()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 2525)).wait()

        let decoder = SMTPResponseDecoder()
        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(decoder), name: SMTPBootstrap.Names.decoder)
        try channel.pipeline.syncOperations.addHandler(SMTPCommandEncoder(), name: SMTPBootstrap.Names.encoder)

        let promise = channel.eventLoop.makePromise(of: NIOAsyncChannel<SMTPReply, SMTPCommand>.self)
        let handler = SMTPBootstrapHandler(
            tls: tls, host: host, tlsConfiguration: .makeClientConfiguration(),
            readyPromise: promise, initialDecoder: decoder
        )
        try channel.pipeline.syncOperations.addHandler(handler)
        return Built(channel: channel, decoder: decoder, promise: promise)
    }
}

/// `EmbeddedChannel.pipeline.removeHandler`'s reentrant-safe removal path
/// (needed when a handler removes another handler, or itself, from within
/// that handler's own callback -- exactly what `SMTPBootstrapHandler`'s
/// STARTTLS swap does) defers the actual pipeline mutation onto the
/// event loop's task queue rather than applying it inline, to avoid
/// corrupting an in-progress dispatch. A real `SelectableEventLoop` drains
/// that queue on its own; `EmbeddedEventLoop` does not run automatically --
/// tests must pump it explicitly after any `writeInbound` that might have
/// triggered a deferred pipeline mutation (handler add/remove).
func pump(_ channel: EmbeddedChannel) {
    channel.embeddedEventLoop.run()
}

/// Writes `buffer` into `channel`'s inbound side, discarding any thrown
/// error -- used by tests that intentionally trigger a pipeline-level
/// failure (e.g. the STARTTLS injection tests) where the interesting
/// assertion is on the bootstrap promise's outcome, not on whether
/// `writeInbound` itself happened to propagate the failure synchronously.
func writeInboundIgnoringError(_ channel: EmbeddedChannel, _ buffer: ByteBuffer) {
    do {
        try channel.writeInbound(buffer)
    } catch {
        // Intentionally discarded -- see doc comment above.
    }
}

/// Reads and discards the next outbound command line written by the
/// bootstrap handler, asserting it equals `expected` (ignoring the
/// trailing CRLF the encoder appends).
func expectOutboundLine(_ channel: EmbeddedChannel, _ expected: String) throws {
    guard var buffer = try channel.readOutbound(as: ByteBuffer.self) else {
        throw TestHelperError.noOutboundData(expected: expected)
    }
    let text = buffer.readString(length: buffer.readableBytes) ?? ""
    guard text == expected + "\r\n" else {
        throw TestHelperError.unexpectedOutboundLine(expected: expected, actual: text)
    }
}

enum TestHelperError: Error, CustomStringConvertible {
    case noOutboundData(expected: String)
    case unexpectedOutboundLine(expected: String, actual: String)

    var description: String {
        switch self {
        case .noOutboundData(let expected): return "expected outbound line \(expected.debugDescription), got nothing"
        case .unexpectedOutboundLine(let expected, let actual):
            return "expected outbound line \(expected.debugDescription), got \(actual.debugDescription)"
        }
    }
}

/// A minimal, deterministic scripted-server driver for `SMTPConnection`
/// (Phase B) tests: wraps a `NIOAsyncTestingChannel` pair -- our
/// `SMTPConnection` reads/writes through the "client" side; the test body
/// plays the "server" role directly against the same channel via
/// `writeInbound`/`waitForOutboundWrite`.
enum ConnectionHarness {
    /// `replyTimeout`/`dataTerminationTimeout` default to
    /// `SMTPConnection.init`'s own production defaults (300s/600s) so every
    /// existing call site is unaffected; FIX #4's timeout regression test
    /// overrides `replyTimeout` to a short, real-time-bounded value instead
    /// (`Task.sleep`-based, not tied to `NIOAsyncTestingEventLoop`'s virtual
    /// clock, so no `advanceTime` dance is needed to observe it fire).
    static func make(
        replyTimeout: TimeInterval = 300,
        dataTerminationTimeout: TimeInterval = 600,
        ehloHostname: String = "client.example.com",
        answersQUIT: Bool = false
    ) async throws -> (SMTPConnection, NIOAsyncTestingChannel) {
        let testingChannel = NIOAsyncTestingChannel()
        try await testingChannel.testingEventLoop.executeInContext {
            if answersQUIT {
                try testingChannel.pipeline.syncOperations.addHandler(QUITResponder(), position: .first)
            }
            try testingChannel.pipeline.syncOperations.addHandler(ByteToMessageHandler(SMTPResponseDecoder()))
            try testingChannel.pipeline.syncOperations.addHandler(SMTPCommandEncoder())
        }
        let asyncChannel = try await testingChannel.testingEventLoop.executeInContext {
            try NIOAsyncChannel<SMTPReply, SMTPCommand>(wrappingChannelSynchronously: testingChannel)
        }
        let connection = SMTPConnection(
            asyncChannel: asyncChannel,
            ehloHostname: ehloHostname,
            replyTimeout: replyTimeout,
            dataTerminationTimeout: dataTerminationTimeout
        )
        return (connection, testingChannel)
    }
}

/// Writes one scripted server reply line into `channel`'s inbound side.
func serverSend(_ channel: NIOAsyncTestingChannel, _ line: String) async throws {
    var buffer = ByteBuffer()
    buffer.writeString(line + "\r\n")
    try await channel.writeInbound(buffer)
}

/// Reads and asserts the next command the client (our code under test)
/// wrote, as a decoded line (without CRLF).
func expectClientLine(_ channel: NIOAsyncTestingChannel) async throws -> String {
    var buffer = try await channel.waitForOutboundWrite(as: ByteBuffer.self)
    let raw = buffer.readString(length: buffer.readableBytes) ?? ""
    return trimCRLF(raw)
}

/// `Result.init(catching:)` has no `async` overload in the standard
/// library; this is the async equivalent, used by tests that need to
/// assert on a thrown error from an `async let` without the whole test
/// function itself throwing (e.g. asserting a specific error case rather
/// than just "it threw").
func resultOf<T: Sendable>(_ body: () async throws -> T) async -> Result<T, Error> {
    do {
        return .success(try await body())
    } catch {
        return .failure(error)
    }
}

/// Strips trailing CR/LF. Operates on `unicodeScalars`, not `Character` --
/// Swift's `String` combines an adjacent CR+LF into a single extended
/// grapheme cluster, so a naive `hasSuffix("\r")`/`hasSuffix("\n")` check
/// against `Character`-level suffixes never matches a "\r\n" pair at all.
func trimCRLF(_ s: String) -> String {
    var scalars = s.unicodeScalars
    while let last = scalars.last, last == "\r" || last == "\n" {
        scalars.removeLast()
    }
    return String(scalars)
}

/// Answers a `QUIT` written by the client with `221`, like a real server,
/// so pool tests don't sit out the QUIT reply timeout. Sits first in the
/// pipeline: it sees the encoded bytes on the way out and feeds the reply
/// back up through the decoder. Event-loop confined.
final class QUITResponder: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = Self.unwrapOutboundIn(data)
        let isQUIT = buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes) == "QUIT\r\n"
        context.write(data, promise: promise)
        if isQUIT {
            context.fireChannelRead(NIOAny(ByteBuffer(string: "221 2.0.0 Bye\r\n")))
        }
    }
}

//
//  DirectMXRealSocketTests.swift
//  PerfectSMTPTests
//
//  Every other `DirectMXTransport` test uses the test-only injectable-
//  dialer `init`, which bypasses `makeDialer` (the production dialer that
//  resolves A/AAAA via the injected `MXResolving` and connects through the
//  new `SMTPBootstrap.connect(to:sniHostname:tls:...)` overload) entirely.
//  That leaves the actual production code path -- "resolve an address,
//  connect to it directly rather than re-resolving through the OS
//  resolver" -- exercised only by code review, not by an automated test.
//  This one test closes that gap: a real `NIOPosix` loopback listener, a
//  `FakeMXResolver` handing back its literal `127.0.0.1` address, and
//  `DirectMXTransport`'s real public `init(resolver:config:group:...)`
//  (not the test-dialer seam) driving one full delivery through it.
//
//  Mirrors `STARTTLSRealSocketTests.swift`'s established pattern for a
//  minimal in-process real-socket fake server, but scripts an *accepting*
//  EHLO/MAIL/RCPT/DATA conversation instead of a STARTTLS handshake.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DirectMXRealSocketTests {
    @Test func productionDialerResolvesAndConnectsToARealLoopbackListener() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await AcceptingFakeSMTPServer.start(group: group)

        let resolver = FakeMXResolver(
            mxRecords: ["real.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.real.example")]],
            addresses: ["mx.real.example": [.v4([127, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(
            resolver: resolver,
            // `allowPrivateAddresses: true` -- FIX #2's SSRF-class filter
            // defaults to rejecting `127.0.0.1` (loopback), which is
            // exactly the address this test's fake server listens on.
            // This is the documented opt-out for a deliberate
            // internal-relay-testing use case (see `DirectMXConfig
            // .allowPrivateAddresses`'s doc comment) -- without it, this
            // test's own address would be filtered before ever dialing.
            config: DirectMXConfig(port: server.port, tlsPolicy: .fixed(.none), allowPrivateAddresses: true),
            group: group
        )

        let envelope = try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["rcpt@real.example"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))

        let results = try await transport.send(envelope, message)
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered through the real production dialer, got \(results[0].outcome)")
            return
        }
    }

    /// FIX #2 (milestone security review, SSRF-class filtering): the
    /// counterpart to the test above -- same real, reachable loopback
    /// listener, same resolved `127.0.0.1` address, but *without*
    /// `allowPrivateAddresses: true`. The listener being genuinely
    /// reachable is what makes this decisive: if the filter weren't
    /// actually gating the dial, this would succeed exactly like the test
    /// above. It must instead fail with the new distinct error, proving
    /// the connection was never attempted at all.
    @Test func productionDialerRefusesToDialARealReachableLoopbackListenerWithoutTheOptOut() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await AcceptingFakeSMTPServer.start(group: group)

        let resolver = FakeMXResolver(
            mxRecords: ["ssrf.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.ssrf.example")]],
            addresses: ["mx.ssrf.example": [.v4([127, 0, 0, 1])]]
        )
        // Deliberately the default config -- `allowPrivateAddresses` left
        // at `false` even though `server` is genuinely listening and
        // reachable at this address/port.
        let transport = DirectMXTransport(
            resolver: resolver,
            config: DirectMXConfig(port: server.port, tlsPolicy: .fixed(.none)),
            group: group
        )

        let envelope = try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["rcpt@ssrf.example"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))

        let results = try await transport.send(envelope, message)
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .failed(let error) = results[0].outcome else {
            Issue.record("expected .failed (the loopback address filtered as private), got \(results[0].outcome)")
            return
        }
        guard let directMXError = error as? DirectMXError,
              case .allResolvedAddressesFilteredAsPrivate(let host) = directMXError
        else {
            Issue.record("expected DirectMXError.allResolvedAddressesFilteredAsPrivate, got \(error)")
            return
        }
        #expect(host == "mx.ssrf.example")
    }

    /// Release review: `0.0.0.0` (and its IPv4-mapped and 6to4 forms)
    /// reaches the local host on macOS and Linux, and used to pass the
    /// private-address filter. With a real listener on 127.0.0.1, the dial
    /// must be refused rather than reaching it.
    @Test(arguments: [DNSAddress.v4([0, 0, 0, 0]), .v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0])])
    func productionDialerRefusesTheUnspecifiedAddressThatReachesLocalhost(address: DNSAddress) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await AcceptingFakeSMTPServer.start(group: group)
        let resolver = FakeMXResolver(
            mxRecords: ["zero.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.zero.example")]],
            addresses: ["mx.zero.example": [address]]
        )
        let transport = DirectMXTransport(
            resolver: resolver, config: DirectMXConfig(port: server.port, tlsPolicy: .fixed(.none)), group: group
        )
        let envelope = try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["rcpt@zero.example"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))

        let results = try await transport.send(envelope, message)
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        guard case .failed(let error)? = results.first?.outcome,
              case .allResolvedAddressesFilteredAsPrivate? = error as? DirectMXError
        else {
            Issue.record("expected the address to be filtered as private, got \(String(describing: results.first?.outcome))")
            return
        }
    }
}

/// A minimal, real-socket fake SMTP server that accepts a full EHLO / MAIL
/// FROM / RCPT TO / DATA conversation and always replies positively. Line
/// framing is hand-rolled (LF-terminated, tolerating a missing CR), same
/// simplification `STARTTLSRealSocketTests.swift`'s `FakeSMTPServer` makes,
/// for the same reason (test-only, trusted input).
private enum AcceptingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(AcceptingFakeSMTPServerHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw AcceptingFakeSMTPServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private enum AcceptingFakeSMTPServerError: Error { case noLocalPort }

private final class AcceptingFakeSMTPServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private var inData = false

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        if inData {
            drainDataPhaseIfTerminated(context: context)
            return
        }
        while let line = extractLine() {
            handle(line: line, context: context)
        }
    }

    private func extractLine() -> String? {
        guard let lfIndex = accumulated.readableBytesView.firstIndex(of: 0x0A) else { return nil }
        let length = lfIndex - accumulated.readerIndex
        guard let bytes = accumulated.readBytes(length: length) else { return nil }
        accumulated.moveReaderIndex(forwardBy: 1)
        var text = String(decoding: bytes, as: UTF8.self)
        if text.hasSuffix("\r") { text.removeLast() }
        return text
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250 fake.example Hello")
        } else if upper.hasPrefix("MAIL FROM") {
            writeLine(context: context, "250 2.1.0 OK")
        } else if upper.hasPrefix("RCPT TO") {
            writeLine(context: context, "250 2.1.5 OK")
        } else if upper == "DATA" {
            writeLine(context: context, "354 Go ahead")
            inData = true
            drainDataPhaseIfTerminated(context: context)
        }
    }

    /// The DATA payload is raw dot-stuffed bytes, not CRLF-delimited
    /// command lines -- once `DATA` has been accepted, just watch for the
    /// terminating `<CRLF>.<CRLF>` sequence across however many reads it
    /// takes to arrive, rather than trying to reuse `extractLine`'s
    /// line-oriented framing.
    private func drainDataPhaseIfTerminated(context: ChannelHandlerContext) {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x2E, 0x0D, 0x0A] // "\r\n.\r\n"
        guard accumulated.readableBytesView.count >= terminator.count,
              Array(accumulated.readableBytesView.suffix(terminator.count)) == terminator
        else { return }
        accumulated.moveReaderIndex(forwardBy: accumulated.readableBytes)
        inData = false
        writeLine(context: context, "250 2.0.0 Queued as 12345")
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

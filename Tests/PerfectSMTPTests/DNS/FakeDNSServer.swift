//
//  FakeDNSServer.swift
//  PerfectSMTPTests
//
//  A minimal, real-socket (not `EmbeddedChannel`) fake DNS server, in the
//  same spirit as `STARTTLSRealSocketTests.swift`'s `FakeSMTPServer`: a
//  `DatagramBootstrap`/`ServerBootstrap`-backed server bound to
//  `127.0.0.1`, driven by a small canned-response script, used by
//  `DNSTransportTests` (TCP fallback on truncation, query-ID-mismatch
//  rejection, UDP-loss/retry/timeout) and
//  `DNSResolverCNAMEFollowingTests` (the CNAME-chain bound + cycle guard --
//  neither is practical to test through `DNSResolver.processMXAnswers`-style
//  pure functions, since chain-following genuinely spans multiple queries).
//
//  Both the UDP and TCP listeners bind to the *same* port number (the OS
//  assigns the UDP port; the TCP listener is then explicitly bound to that
//  same numeric port on the independent TCP namespace) -- matching how a
//  real DNS server listens on one port number across both protocols, since
//  `DNSTransport`'s TCP fallback always retries against the exact
//  `SocketAddress` the truncated UDP response came from.
//

import NIOCore
import NIOPosix
@testable import PerfectSMTP

enum FakeDNSServer {
    struct Running {
        let nameserver: SocketAddress
        let udpChannel: Channel
        let tcpChannel: Channel?

        func shutdown() async {
            try? await udpChannel.close()
            if let tcpChannel { try? await tcpChannel.close() }
        }
    }

    enum ServerError: Error {
        case noLocalPort
    }

    /// `"\(type.rawValue)|\(name.lowercased())"` -- the key format both
    /// handlers below use to look up a canned response for an incoming
    /// query.
    static func scriptKey(name: String, type: DNSRecordType) -> String {
        "\(type.rawValue)|\(name.lowercased())"
    }

    /// Binds UDP to a free port, then TCP to the same port number (a
    /// resolver falls back to TCP on the nameserver's own port). The TCP
    /// port can already be taken -- under a parallel test run another
    /// test's connection may hold it -- which made the TCP-fallback test
    /// fail intermittently with "Address already in use". The TCP listener
    /// sets `SO_REUSEADDR` (covers a lingering TIME_WAIT socket), and on a
    /// TCP bind failure this closes the UDP channel and tries a fresh port,
    /// up to `maxAttempts` times (covers a live socket on that port).
    static func start(
        group: any EventLoopGroup,
        udpResponses: [String: FakeDNSUDPHandler.ScriptedResponse],
        tcpResponses: [String: [UInt8]] = [:],
        maxAttempts: Int = 20
    ) async throws -> Running {
        var attempt = 1
        while true {
            let udpChannel = try await DatagramBootstrap(group: group)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(FakeDNSUDPHandler(responses: udpResponses))
                    }
                }
                .bind(host: "127.0.0.1", port: 0)
                .get()
            guard let port = udpChannel.localAddress?.port else {
                try? await udpChannel.close()
                throw ServerError.noLocalPort
            }

            var tcpChannel: Channel?
            if !tcpResponses.isEmpty {
                do {
                    tcpChannel = try await ServerBootstrap(group: group)
                        // A TIME_WAIT socket from an earlier connection on
                        // this port number would otherwise block the bind.
                        .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                        .childChannelInitializer { channel in
                            channel.eventLoop.makeCompletedFuture {
                                try channel.pipeline.syncOperations.addHandler(
                                    ByteToMessageHandler(DNSTCPFrameDecoder()), name: "dns-tcp-frame-decoder"
                                )
                                try channel.pipeline.syncOperations.addHandler(FakeDNSTCPHandler(responses: tcpResponses))
                            }
                        }
                        .bind(host: "127.0.0.1", port: port)
                        .get()
                } catch {
                    try? await udpChannel.close()
                    guard attempt < maxAttempts else { throw error }
                    attempt += 1
                    continue
                }
            }

            let nameserver = try SocketAddress(ipAddress: "127.0.0.1", port: port)
            return Running(nameserver: nameserver, udpChannel: udpChannel, tcpChannel: tcpChannel)
        }
    }
}

/// The UDP side of the fake server. For each incoming datagram, decodes
/// just enough (via the real `DNSMessage.decode`) to find the question,
/// looks up a canned response by `FakeDNSServer.scriptKey`, and -- if
/// found -- sends it back with the response's transaction ID overwritten
/// to match the incoming query (a real ID is randomized per query, so a
/// static fixture must be ID-patched at send time). A query with no
/// scripted response is silently dropped, simulating ordinary UDP loss
/// (exercises `DNSTransport`'s retry/timeout path).
final class FakeDNSUDPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    struct ScriptedResponse {
        let bytes: [UInt8]
        /// If `true`, a decoy response with a deliberately wrong
        /// transaction ID is sent immediately before the real one --
        /// `DNSTransportTests` uses this to confirm the resolver doesn't
        /// accept a stray/mismatched reply as answering the pending query.
        var precededByWrongID = false

        init(_ bytes: [UInt8], precededByWrongID: Bool = false) {
            self.bytes = bytes
            self.precededByWrongID = precededByWrongID
        }
    }

    let responses: [String: ScriptedResponse]

    init(responses: [String: ScriptedResponse]) {
        self.responses = responses
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = Self.unwrapInboundIn(data)
        let queryBytes = [UInt8](envelope.data.readableBytesView)
        guard let decodedQuery = try? DNSMessage.decode(queryBytes), let question = decodedQuery.questions.first else {
            return
        }
        guard let scripted = responses[FakeDNSServer.scriptKey(name: question.name, type: DNSRecordType(rawValue: question.type) ?? .a)] else {
            return // no script entry: simulate a dropped/lost query
        }

        if scripted.precededByWrongID {
            var decoy = scripted.bytes
            // Adding 256 (mod 65536) to the real query's ID is always a
            // different 16-bit value -- a deterministic, always-wrong ID
            // rather than a coin-flip chance of accidentally matching.
            decoy[0] = queryBytes[0] &+ 1
            decoy[1] = queryBytes[1]
            send(decoy, to: envelope.remoteAddress, context: context)
        }

        var real = scripted.bytes
        real[0] = queryBytes[0]
        real[1] = queryBytes[1]
        send(real, to: envelope.remoteAddress, context: context)
    }

    private func send(_ bytes: [UInt8], to address: SocketAddress, context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        context.writeAndFlush(Self.wrapOutboundOut(AddressedEnvelope(remoteAddress: address, data: buffer)), promise: nil)
    }
}

/// The TCP side, used only for the truncation-fallback test. Sits behind
/// `DNSTCPFrameDecoder` in the pipeline (the same length-prefix decoder
/// production code uses), so this handler's `InboundIn` is already one
/// complete, de-framed DNS message.
final class FakeDNSTCPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    let responses: [String: [UInt8]]

    init(responses: [String: [UInt8]]) {
        self.responses = responses
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = Self.unwrapInboundIn(data)
        let queryBytes = [UInt8](frame.readableBytesView)
        guard let decodedQuery = try? DNSMessage.decode(queryBytes), let question = decodedQuery.questions.first else {
            return
        }
        guard var responseBytes = responses[FakeDNSServer.scriptKey(name: question.name, type: DNSRecordType(rawValue: question.type) ?? .a)] else {
            return
        }
        responseBytes[0] = queryBytes[0]
        responseBytes[1] = queryBytes[1]
        var framed = context.channel.allocator.buffer(capacity: responseBytes.count + 2)
        framed.writeInteger(UInt16(responseBytes.count))
        framed.writeBytes(responseBytes)
        context.writeAndFlush(Self.wrapOutboundOut(framed), promise: nil)
    }
}

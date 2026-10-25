//
//  DNSTransport.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3, point 2: UDP query/response with timeout + retry, TCP
//  fallback on truncation. This is the only file in `Sources/PerfectSMTP/DNS`
//  that touches NIO -- `DNSWireFormat.swift` is pure `[UInt8]`,
//  `DNSResolver.swift`'s MX/CNAME logic is pure `DNSMessage`. Both bytes and
//  message decoding are unit-testable with no channel at all; this file is
//  what a fake-UDP/TCP-server integration test (`DNSTransportTests.swift`)
//  exercises.
//
//  Each query dials a **fresh** channel (UDP: bind ephemeral port 0, one
//  request/response, close; TCP: connect, one request/response, close) --
//  deliberately not pooled, unlike `SMTPConnectionPool`. A DNS query is a
//  one-shot request/response, not a multi-command conversation that
//  benefits from connection reuse, so this uses `NIOAsyncChannel.executeThenClose`
//  (the *documented*, request-scoped-lifetime way to use the async bridge --
//  see `SMTPConnection.swift`'s doc comment for why *that* type deliberately
//  deviates from `executeThenClose` for its own, differently-shaped,
//  pooled-connection use case; this file is the more conventional usage the
//  API was actually designed around).
//
//  Anti-spoofing hygiene (plan's explicit ask, "don't overengineer"):
//  binding UDP to port 0 gets an OS-assigned ephemeral source port for
//  free; every inbound datagram is checked against the nameserver address
//  actually queried before being considered at all, and every decoded
//  response's 16-bit transaction ID is checked against the query's
//  (randomly chosen per `DNSResolver.query`) ID before being accepted --
//  anything that fails either check is silently discarded and the wait
//  continues (bounded by the surrounding timeout), never treated as an
//  error in its own right, since an off-path attacker's forged packet (or
//  simply a stray/late reply to an earlier, already-abandoned attempt)
//  arriving is not itself a failure of the real query still in flight.
//

import NIOCore
import NIOPosix

enum DNSTransport {
    /// Number of UDP attempts made against one nameserver before moving on
    /// to the next configured nameserver. UDP loss is normal and expected
    /// (plan's explicit framing) -- this is *not* "assume the network is
    /// broken after one dropped packet."
    private static let maximumUDPAttemptsPerNameserver = 3

    /// Backoff between UDP retries against the *same* nameserver,
    /// multiplied by the attempt number (attempt 1 -> 200ms, attempt 2 ->
    /// 400ms). Deliberately small relative to `queryTimeout` -- this is
    /// about spacing out retries after a lost packet, not a slow degrading
    /// backoff (that's `DirectMXTransport`'s retry-queue territory, for
    /// whole-delivery-attempt retries, not one UDP datagram).
    private static let udpRetryBackoffUnit = Int64(200)

    static func query(name: String, type: DNSRecordType, resolver: DNSResolver) async throws -> DNSMessage {
        let id = UInt16.random(in: .min ... .max)
        let queryBytes = try DNSMessage.encodeQuery(id: id, name: name, type: type)

        var lastError: any Error = DNSResolver.ResolveError.timeout
        for nameserver in resolver.nameservers {
            for attempt in 0..<maximumUDPAttemptsPerNameserver {
                do {
                    let response = try await withTimeout(resolver.queryTimeout) {
                        try await sendUDPQuery(
                            to: nameserver, message: queryBytes, expectedID: id, name: name, type: type, group: resolver.group
                        )
                    }
                    if response.header.truncated {
                        let tcpResponse = try await withTimeout(resolver.queryTimeout) {
                            try await sendTCPQuery(
                                to: nameserver, message: queryBytes, expectedID: id, name: name, type: type, group: resolver.group
                            )
                        }
                        try DNSResolver.validateResponseCode(tcpResponse)
                        return tcpResponse
                    }
                    try DNSResolver.validateResponseCode(response)
                    return response
                } catch let error as DNSResolver.ResolveError where error == .timeout {
                    lastError = error
                    if attempt + 1 < maximumUDPAttemptsPerNameserver {
                        try? await Task.sleep(nanoseconds: UInt64(udpRetryBackoffUnit * Int64(attempt + 1)) * 1_000_000)
                    }
                    continue // retry the same nameserver
                } catch {
                    lastError = error
                    break // a non-timeout failure (malformed/serverFailure/connection error) -- try the next nameserver, not more retries against this one
                }
            }
        }
        throw lastError
    }

    // MARK: - UDP

    private static func sendUDPQuery(
        to nameserver: SocketAddress, message: [UInt8], expectedID: UInt16, name: String, type: DNSRecordType,
        group: any EventLoopGroup
    ) async throws -> DNSMessage {
        let channel = try await DatagramBootstrap(group: group)
            .bind(host: wildcardBindHost(for: nameserver), port: 0)
            .get()

        let asyncChannel: NIOAsyncChannel<AddressedEnvelope<ByteBuffer>, AddressedEnvelope<ByteBuffer>>
        do {
            asyncChannel = try await channel.eventLoop.submit {
                try NIOAsyncChannel(wrappingChannelSynchronously: channel)
            }.get()
        } catch {
            try? await channel.close()
            throw error
        }

        return try await asyncChannel.executeThenClose { inbound, outbound in
            var buffer = channel.allocator.buffer(capacity: message.count)
            buffer.writeBytes(message)
            try await outbound.write(AddressedEnvelope(remoteAddress: nameserver, data: buffer))

            for try await envelope in inbound {
                // Anti-spoofing: only consider datagrams that actually came
                // from the nameserver we queried.
                guard envelope.remoteAddress == nameserver else { continue }
                let responseBytes = [UInt8](envelope.data.readableBytesView)
                // Release review: a malformed or mismatched datagram is
                // ignored and the wait continues, so one spoofed packet
                // can't abort the lookup; the real reply (or the timeout)
                // still decides. TCP, below, has no such spoofing surface.
                guard let decoded = try? DNSMessage.decode(responseBytes),
                      isValidResponse(decoded, expectedID: expectedID, name: name, type: type)
                else { continue }
                return decoded
            }
            throw DNSResolver.ResolveError.timeout
        }
    }

    private static func wildcardBindHost(for nameserver: SocketAddress) -> String {
        if case .v6 = nameserver { return "::" }
        return "0.0.0.0"
    }

    // MARK: - TCP (RFC 1035 §4.2.2 fallback on a truncated UDP response)

    private static func sendTCPQuery(
        to nameserver: SocketAddress, message: [UInt8], expectedID: UInt16, name: String, type: DNSRecordType,
        group: any EventLoopGroup
    ) async throws -> DNSMessage {
        let channel = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        ByteToMessageHandler(DNSTCPFrameDecoder(), maximumBufferSize: 65_535 + 2),
                        name: "dns-tcp-frame-decoder"
                    )
                }
            }
            .connect(to: nameserver)
            .get()

        let asyncChannel: NIOAsyncChannel<ByteBuffer, ByteBuffer>
        do {
            asyncChannel = try await channel.eventLoop.submit {
                try NIOAsyncChannel(wrappingChannelSynchronously: channel)
            }.get()
        } catch {
            try? await channel.close()
            throw error
        }

        return try await asyncChannel.executeThenClose { inbound, outbound in
            var framed = channel.allocator.buffer(capacity: message.count + 2)
            framed.writeInteger(UInt16(message.count))
            framed.writeBytes(message)
            try await outbound.write(framed)

            for try await frame in inbound {
                let responseBytes = [UInt8](frame.readableBytesView)
                let decoded: DNSMessage
                do {
                    decoded = try DNSMessage.decode(responseBytes)
                } catch {
                    throw DNSResolver.ResolveError.malformedResponse
                }
                // TCP is connection-oriented (the OS already validated the
                // three-way handshake against `nameserver`, unlike UDP), so
                // there's no equivalent source-address spoofing surface --
                // the transaction-ID check is still applied for
                // defense-in-depth and consistency with the UDP path.
                guard isValidResponse(decoded, expectedID: expectedID, name: name, type: type) else { continue }
                return decoded
            }
            throw DNSResolver.ResolveError.timeout
        }
    }

    // MARK: - Shared response validation

    /// The basic anti-spoofing check applied to every UDP/TCP response
    /// before it's trusted: it must actually be a response (`QR=1`, not an
    /// echoed-back query) and its transaction ID must match the query it's
    /// supposedly answering. Factored out as a pure, `internal` function
    /// (not folded inline into the read loops above) specifically so
    /// `DNSTransportTests` can unit-test "a response with the wrong ID is
    /// rejected" as a deterministic, non-networked check, rather than only
    /// being able to exercise it indirectly through a live UDP exchange.
    static func isValidResponse(_ message: DNSMessage, expectedID: UInt16) -> Bool {
        message.header.isResponse && message.header.id == expectedID
    }

    /// `isValidResponse(_:expectedID:)` plus (release review) the question
    /// section: exactly one question, echoing the name (case-insensitively)
    /// and type that were asked.
    static func isValidResponse(_ message: DNSMessage, expectedID: UInt16, name: String, type: DNSRecordType) -> Bool {
        guard isValidResponse(message, expectedID: expectedID), message.questions.count == 1 else { return false }
        let question = message.questions[0]
        return question.type == type.rawValue && DNSResolver.sameName(question.name, name)
    }

    // MARK: - Timeout

    private static func withTimeout<T: Sendable>(
        _ timeout: TimeAmount, _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { race in
            race.addTask { try await operation() }
            race.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(0, timeout.nanoseconds)))
                throw DNSResolver.ResolveError.timeout
            }
            defer { race.cancelAll() }
            guard let result = try await race.next() else { throw DNSResolver.ResolveError.timeout }
            return result
        }
    }
}

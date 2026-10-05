//
//  SMTPConnection.swift
//  PerfectSMTP
//
//  Phase B of the two-phase channel lifecycle (plan §4.3): native
//  async/await, no hand-rolled correlation at all. Once bootstrap (Phase A)
//  hands back a pipeline-clean `NIOAsyncChannel<SMTPReply, SMTPCommand>`,
//  everything from EHLO onward — capability re-negotiation, AUTH's SASL
//  exchange (including the `async` token-refresh callback), MAIL/RCPT/DATA,
//  PIPELINING — is driven as a plain `for try await reply in inboundStream`
//  loop paired with `try await outboundWriter.write(command)`. SMTP replies
//  are guaranteed to arrive in the same order commands were issued (RFC
//  2920 §3, including under PIPELINING), so this needs no shared
//  correlation structure: this object's owning task is the only reader and
//  the only writer, sequentially, within one `async` function.
//

import Foundation
import NIOCore

/// Errors specific to driving a live Phase-B conversation (as opposed to
/// `SMTPError`, which classifies SMTP-level replies).
public enum SMTPConnectionError: Error, Sendable, Equatable {
    /// The `NIOAsyncChannel` inbound sequence ended (channel closed) while
    /// a reply was still expected.
    case channelClosedByPeer
    /// A `334` continuation reply's text wasn't valid base64.
    case malformedSASLChallenge
    /// FIX #4 (plan §7, required, milestone architecture review): no reply
    /// arrived within the configured timeout. RFC 5321 §4.5.3.2 specifies
    /// minimum client timeouts per command phase -- without enforcing one,
    /// a hung/black-holed remote server leaves the awaiting task suspended
    /// forever, and since the connection never becomes "idle" (it's
    /// mid-transaction), the pool's idle-eviction path never reaps it
    /// either, silently shrinking `maxPerHost`'s effective capacity toward
    /// zero over time. Flows through `SMTPConnectionPool.withConnection`'s
    /// existing catch path exactly like any other thrown error, marking the
    /// connection unhealthy (closed, not returned to idle) via `release`.
    case replyTimedOut
}

/// The live, TLS-ready connection's async conversation surface.
///
/// `@unchecked Sendable`: used by a single connection-owning task at a
/// time — the connection pool (`SMTPConnectionPool`) enforces
/// checkout/release exclusivity (plan §4.4's "connections never cross
/// tasks"), matching PerfectNIO's `AsyncWebSocket` precedent (single-task
/// ownership, not internal synchronization, is the safety argument).
///
/// Long-lived across many pool checkouts, so this deliberately does **not**
/// use `NIOAsyncChannel.executeThenClose` (which closes the channel the
/// moment its scoped closure returns — the wrong lifetime for a pooled,
/// reused connection). It instead uses the (deprecated, but still
/// functional) `NIOAsyncChannel.inbound`/`.outbound` accessors once, at
/// construction, to obtain a persistent iterator/writer pair that outlives
/// any single call — the documented replacement (`executeThenClose`)
/// assumes a request-scoped lifetime that connection pooling doesn't have.
/// This is a deliberate, documented judgment call (see the Phase 1 report).
public final class SMTPConnection: @unchecked Sendable {
    /// Exposed for the pool's liveness checks (`channel.isActive`) and for
    /// closing a connection being evicted. The connection owns this channel:
    /// it is closed when the connection is deinitialized.
    public let channel: Channel

    private var iterator: NIOAsyncChannelInboundStream<SMTPReply>.AsyncIterator
    private let outbound: NIOAsyncChannelOutboundWriter<SMTPCommand>
    public private(set) var capabilities: Capabilities
    public let ehloHostname: String
    /// FIX #4: per-command timeout (RFC 5321 §4.5.3.2's general minimum is
    /// 5 minutes; 300s here matches that). Applied uniformly across
    /// `nextReply()`/`write()` as a documented simplification -- threading
    /// a phase-specific value through every call site was judged too
    /// invasive for this fix pass, except for the one place it matters most
    /// (see `dataTerminationTimeout` below).
    private let replyTimeout: TimeInterval
    /// FIX #4's phase-specific exception: RFC 5321 §4.5.3.2 specifies a
    /// *longer* minimum timeout (10 minutes) specifically for the client
    /// waiting on the final reply after the DATA-terminating `<CRLF>.<CRLF>`
    /// -- the server may be doing real work (spooling/scanning/reinjecting
    /// a large message) that legitimately takes longer than an ordinary
    /// command round-trip. Used only in `sendBodyAndFinalize`'s final-reply
    /// wait; every other command uses `replyTimeout`.
    private let dataTerminationTimeout: TimeInterval
    /// FIX (plan §4.8, Phase 3 follow-through on Phase 1's own deferred
    /// item): the 421-vs-greylist-vs-other-4yz backoff durations applied by
    /// `outcomeFor` below. Defaults to the exact values Phase 1 originally
    /// hardcoded, so every existing caller (`RelayTransport`,
    /// `LocalMTATransport`'s N/A here, and every Phase 1/2 test) is
    /// unaffected unless it opts in to a different policy.
    /// `DirectMXTransport` passes its own `DirectMXRetryQueue`'s configured
    /// policy here, so a RCPT/DATA-phase rejection and a MAIL-FROM-phase
    /// rejection for the same destination get the identical configured
    /// backoff instead of two independently-hardcoded copies of it.
    private let backoffPolicy: RetryBackoffPolicy

    public init(
        asyncChannel: NIOAsyncChannel<SMTPReply, SMTPCommand>,
        ehloHostname: String,
        replyTimeout: TimeInterval = 300,
        dataTerminationTimeout: TimeInterval = 600,
        backoffPolicy: RetryBackoffPolicy = .init()
    ) {
        self.channel = asyncChannel.channel
        // Intentional use of the unscoped, deprecated `.inbound`/`.outbound`
        // accessors -- see this type's doc comment for why
        // `executeThenClose`'s request-scoped lifetime doesn't fit a
        // pooled, reused connection. The two deprecation warnings below are
        // deliberately left visible rather than suppressed, as an honest
        // signal of this judgment call to anyone reading build output.
        self.iterator = asyncChannel.inbound.makeAsyncIterator()
        self.outbound = asyncChannel.outbound
        self.capabilities = Capabilities()
        self.ehloHostname = ehloHostname
        self.replyTimeout = replyTimeout
        self.dataTerminationTimeout = dataTerminationTimeout
        self.backoffPolicy = backoffPolicy
    }

    /// `NIOAsyncChannel(wrappingChannelSynchronously:)` creates the outbound
    /// writer with `finishOnDeinit: false`, which traps ("Deinited
    /// NIOAsyncWriter without calling finish()") if the last reference to
    /// an unfinished writer goes away. Today the channel handler happens to
    /// hold its own reference until the channel closes, because
    /// `SMTPBootstrap` wraps an already-active channel, but a channel that
    /// activates after wrapping makes this connection the only owner. The
    /// pool closes connections with a fire-and-forget `close(promise: nil)`
    /// and drops them at once, so finish the writer here rather than rely
    /// on that NIO detail. With outbound half-closure disabled (the
    /// default) finishing the writer doesn't touch the channel itself, so
    /// close it too: nothing else owns the channel once its connection is
    /// gone, and a connection dropped without being closed would otherwise
    /// leak its socket. The `isActive` check skips channels the pool has
    /// already closed: `close` always hops to the event loop, which logs an
    /// error (or traps under `SWIFTNIO_STRICT`) if the group has since shut
    /// down. Shutting down a group closes its channels, so an active
    /// channel always has a live loop.
    deinit {
        outbound.finish()
        if channel.isActive {
            channel.close(promise: nil)
        }
    }

    /// Reads the next reply, or throws if the connection closed
    /// mid-conversation (plan §4.3's "mid-conversation disconnect" —
    /// `NIOAsyncChannel`'s inbound sequence terminating on channel close
    /// surfaces here as a normal thrown error by construction, no special
    /// handling needed), or throws `.replyTimedOut` if `replyTimeout`
    /// elapses first (FIX #4).
    public func nextReply() async throws -> SMTPReply {
        try await raceAgainstTimeout(replyTimeout) { try await self.rawNextReply() }
    }

    /// The actual, un-timed-out read off the inbound iterator -- factored
    /// out so `sendBodyAndFinalize` can race it against
    /// `dataTerminationTimeout` instead of `nextReply()`'s `replyTimeout`.
    private func rawNextReply() async throws -> SMTPReply {
        guard let reply = try await iterator.next() else {
            throw SMTPConnectionError.channelClosedByPeer
        }
        return reply
    }

    /// Races `operation` against `timeout`, matching the shape of
    /// `LocalMTATransport.raceTerminationAgainstTimeout` for consistency
    /// (FIX #4's explicit instruction to reuse that pattern). The loser is
    /// cancelled; `withThrowingTaskGroup` itself blocks this function's
    /// return on that cancellation actually completing, same as the
    /// existing precedent.
    private func raceAgainstTimeout<T: Sendable>(
        _ timeout: TimeInterval,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { race in
            race.addTask { try await operation() }
            race.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(0, timeout) * 1_000_000_000))
                throw SMTPConnectionError.replyTimedOut
            }
            defer { race.cancelAll() }
            guard let result = try await race.next() else {
                throw SMTPConnectionError.replyTimedOut
            }
            return result
        }
    }

    public func write(_ command: SMTPCommand) async throws {
        try await raceAgainstTimeout(replyTimeout) { try await self.outbound.write(command) }
    }

    public func writeLine(_ line: String) async throws {
        try await write(.line(line))
    }

    /// Phase B's first command (plan §4.3 step 7): EHLO, with a HELO
    /// fallback when the server doesn't understand EHLO at all.
    @discardableResult
    public func negotiateCapabilities() async throws -> Capabilities {
        try await writeLine("EHLO \(ehloHostname)")
        let reply = try await nextReply()
        if reply.replyClass == .permanentNegative {
            try await writeLine("HELO \(ehloHostname)")
            let heloReply = try await nextReply()
            guard heloReply.replyClass == .positiveCompletion else {
                throw SMTPError.classify(heloReply)
            }
            capabilities = Capabilities()
            return capabilities
        }
        guard reply.replyClass == .positiveCompletion else {
            throw SMTPError.classify(reply)
        }
        capabilities = Capabilities(parsingEHLOLines: reply.lines)
        return capabilities
    }

    // MARK: - AUTH (plan §4.5)

    /// Tracks whether this connection has already completed an AUTH
    /// exchange — a pooled connection is reused across many checkouts, and
    /// most servers reject a second `AUTH` on an already-authenticated
    /// session (typically `503 5.5.1 already authenticated`); callers
    /// (e.g. `RelayTransport`) should check this before calling
    /// `authenticate(_:)` again on a connection they didn't just dial.
    public private(set) var isAuthenticated = false

    public func authenticate(_ mechanism: any SASLMechanism) async throws {
        guard capabilities.authMechanisms.contains(mechanism.name) else {
            throw SMTPError.authenticationFailed(
                SMTPReply(code: 504, lines: ["Unsupported AUTH mechanism \(mechanism.name)"])
            )
        }
        var attempt = mechanism
        do {
            try await performSASLExchange(&attempt)
        } catch let error as SMTPError {
            guard case .authenticationFailed = error, let xoauth2 = mechanism as? XOAuth2 else { throw error }
            // XOAuth2-specific retry (plan §4.5): call tokenProvider() again
            // and retry once. A fresh `XOAuth2` value (same tokenProvider
            // closure) naturally re-invokes it during the retried exchange
            // -- no separate refresh hook needed on the protocol.
            var retry: any SASLMechanism = XOAuth2(username: xoauth2.username, tokenProvider: xoauth2.tokenProvider)
            try await performSASLExchange(&retry)
            isAuthenticated = true
            return
        }
        isAuthenticated = true
    }

    private func performSASLExchange(_ mechanism: inout any SASLMechanism) async throws {
        let initial = try await mechanism.initialResponse()
        var line = "AUTH \(mechanism.name)"
        if let initial {
            line += " \(Data(initial).base64EncodedString())"
        }
        try await writeLine(line)
        var reply = try await nextReply()
        while reply.code == 334 {
            guard let challengeText = reply.lines.first,
                  let challengeData = Data(base64Encoded: challengeText)
            else {
                throw SMTPConnectionError.malformedSASLChallenge
            }
            let response = try await mechanism.respond(to: Array(challengeData))
            try await writeLine(Data(response).base64EncodedString())
            reply = try await nextReply()
        }
        guard reply.replyClass == .positiveCompletion else {
            throw SMTPError.authenticationFailed(reply)
        }
    }

    // MARK: - Mail transaction (plan §4.3's PIPELINING semantics)

    /// Sends one message to `envelope.recipients`, returning one
    /// `DeliveryResult` per recipient. Uses PIPELINING when advertised;
    /// degrades to lock-step (await each reply before the next write) when
    /// absent — the same command sequence either way.
    public func sendMessage(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        var mailFromLine = try envelope.mailFrom.mailFromCommand
        if capabilities.sizeAdvertised {
            mailFromLine += " SIZE=\(message.estimatedSize)"
        }
        let recipientLines = try envelope.recipients.map { recipient -> String in
            let validated = try HeaderEncoder.rejectHeaderInjection(recipient, field: "RCPT TO address")
            return "RCPT TO:<\(validated)>"
        }

        if capabilities.pipelining {
            return try await sendPipelined(
                mailFromLine: mailFromLine, recipientLines: recipientLines,
                recipients: envelope.recipients, message: message
            )
        }
        return try await sendLockStep(
            mailFromLine: mailFromLine, recipientLines: recipientLines,
            recipients: envelope.recipients, message: message
        )
    }

    private func sendLockStep(
        mailFromLine: String, recipientLines: [String], recipients: [String], message: SignedMessage
    ) async throws -> [DeliveryResult] {
        try await writeLine(mailFromLine)
        let mailReply = try await nextReply()
        guard mailReply.replyClass == .positiveCompletion else {
            throw classifyMailFromFailure(mailReply)
        }

        var results: [DeliveryResult] = []
        var anyAccepted = false
        for (recipient, line) in zip(recipients, recipientLines) {
            try await writeLine(line)
            let reply = try await nextReply()
            if reply.replyClass == .positiveCompletion {
                anyAccepted = true
                results.append(DeliveryResult(recipient: recipient, outcome: .delivered(reply)))
            } else {
                results.append(DeliveryResult(recipient: recipient, outcome: outcomeFor(reply)))
            }
        }
        guard anyAccepted else { return results }

        try await writeLine("DATA")
        let dataReply = try await nextReply()
        guard dataReply.code == 354 else {
            let fallback = outcomeFor(dataReply)
            return remapAccepted(results, to: fallback)
        }

        return try await sendBodyAndFinalize(message, results: results)
    }

    private func sendPipelined(
        mailFromLine: String, recipientLines: [String], recipients: [String], message: SignedMessage
    ) async throws -> [DeliveryResult] {
        try await writeLine(mailFromLine)
        for line in recipientLines { try await writeLine(line) }
        try await writeLine("DATA")

        let mailReply = try await nextReply()
        guard mailReply.replyClass == .positiveCompletion else {
            // The server will still reply to every pipelined command it
            // already received even though MAIL FROM failed -- drain them
            // to stay in sync with RFC 2920 §3's in-order-reply guarantee
            // before surfacing the failure.
            for _ in recipientLines { _ = try? await nextReply() }
            _ = try? await nextReply()
            throw classifyMailFromFailure(mailReply)
        }

        var results: [DeliveryResult] = []
        var anyAccepted = false
        for recipient in recipients {
            let reply = try await nextReply()
            if reply.replyClass == .positiveCompletion {
                anyAccepted = true
                results.append(DeliveryResult(recipient: recipient, outcome: .delivered(reply)))
            } else {
                results.append(DeliveryResult(recipient: recipient, outcome: outcomeFor(reply)))
            }
        }

        let dataReply = try await nextReply()
        // DATA proceeds only if at least one RCPT was accepted -- otherwise
        // the pipelined DATA command itself draws a rejection and the body
        // must never be sent (plan §4.3's corrected PIPELINING semantics).
        guard anyAccepted, dataReply.code == 354 else {
            let fallback = outcomeFor(dataReply)
            return remapAccepted(results, to: fallback)
        }

        return try await sendBodyAndFinalize(message, results: results)
    }

    private func sendBodyAndFinalize(
        _ message: SignedMessage, results: [DeliveryResult]
    ) async throws -> [DeliveryResult] {
        try await write(.raw(DotStuffing.encode(message.rfc5322)))
        // The point of no return (plan §4.8): after the DATA payload is
        // sent, before the final reply arrives. A failure in this exact
        // window is `.ambiguous` and must never be auto-retried -- this
        // includes a `.replyTimedOut` (FIX #4): a timeout waiting on the
        // terminating reply is exactly as ambiguous as any other failure
        // here, since the message may or may not have actually been
        // accepted. Uses `dataTerminationTimeout` (not `nextReply()`'s
        // ordinary `replyTimeout`) per RFC 5321 §4.5.3.2's longer minimum
        // for this specific wait.
        let finalOutcome: DeliveryResult.Outcome
        do {
            let finalReply = try await raceAgainstTimeout(dataTerminationTimeout) { try await self.rawNextReply() }
            finalOutcome = finalReply.replyClass == .positiveCompletion
                ? .delivered(finalReply) : outcomeFor(finalReply)
        } catch {
            finalOutcome = .ambiguous(nil)
        }
        return remapAccepted(results, to: finalOutcome)
    }

    /// Replaces every tentatively-`.delivered` (i.e. RCPT-accepted) result
    /// with `outcome` — the actual outcome is only known once the DATA
    /// phase's single final reply arrives, since SMTP has one server reply
    /// covering every accepted recipient, not one per recipient.
    private func remapAccepted(_ results: [DeliveryResult], to outcome: DeliveryResult.Outcome) -> [DeliveryResult] {
        results.map { result in
            if case .delivered = result.outcome {
                return DeliveryResult(recipient: result.recipient, outcome: outcome)
            }
            return result
        }
    }

    private func classifyMailFromFailure(_ reply: SMTPReply) -> SMTPError {
        if reply.code == 552 {
            return .sizeExceeded(limit: capabilities.size ?? 0)
        }
        return SMTPError.classify(reply)
    }

    /// Phase 1's job is correct single-attempt classification, not a full
    /// retry scheduler (plan §4.8's explicit scope boundary — the actual
    /// scheduling/execution of retries is Phase 3 territory). Backoff
    /// durations (per the 421-vs-greylist distinction) come from
    /// `backoffPolicy` -- configurable since Phase 3's follow-through (see
    /// that property's doc comment); Phase 1 callers that never set it get
    /// the exact same 900s/300s/120s values this method originally
    /// hardcoded.
    private func outcomeFor(_ reply: SMTPReply) -> DeliveryResult.Outcome {
        backoffPolicy.classify(reply, attempt: 1)
    }
}

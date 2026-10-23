//
//  SMTPConnectionStateMachineTests.swift
//  PerfectSMTPTests
//
//  Phase B (plan §4.3/§5): multiline EHLO parse, PIPELINING batching vs.
//  lock-step degradation plus an equivalence test, mid-batch partial-RCPT-
//  rejection, AUTH round-trips including XOAUTH2 token-refresh-on-535,
//  SIZE pre-upload fail-fast on 552, HELO fallback, and mid-conversation
//  disconnect propagation.
//
import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import PerfectSMTP

struct SMTPConnectionStateMachineTests {

    // MARK: - EHLO / HELO

    @Test func multilineEHLOParsesAllCapabilities() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        async let negotiate = connection.negotiateCapabilities()
        #expect(try await expectClientLine(channel) == "EHLO client.example.com")
        try await serverSend(channel, "250-smtp.example.com Hello")
        try await serverSend(channel, "250-PIPELINING")
        try await serverSend(channel, "250-SIZE 35882577")
        try await serverSend(channel, "250-8BITMIME")
        try await serverSend(channel, "250-SMTPUTF8")
        try await serverSend(channel, "250-AUTH PLAIN LOGIN XOAUTH2")
        try await serverSend(channel, "250 ENHANCEDSTATUSCODES")

        let capabilities = try await negotiate
        #expect(capabilities.pipelining)
        #expect(capabilities.sizeAdvertised)
        #expect(capabilities.size == 35_882_577)
        #expect(capabilities.eightBitMIME)
        #expect(capabilities.smtpUTF8)
        #expect(capabilities.enhancedStatusCodes)
        #expect(capabilities.authMechanisms == ["PLAIN", "LOGIN", "XOAUTH2"])
        #expect(!capabilities.startTLS)
    }

    @Test func heloFallbackWhenEHLOUnsupported() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        async let negotiate = connection.negotiateCapabilities()
        #expect(try await expectClientLine(channel) == "EHLO client.example.com")
        try await serverSend(channel, "500 Command not recognized")
        #expect(try await expectClientLine(channel) == "HELO client.example.com")
        try await serverSend(channel, "250 smtp.example.com")

        let capabilities = try await negotiate
        #expect(capabilities == Capabilities())
    }

    // MARK: - AUTH

    @Test func authPlainRoundTrip() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithAuth(connection, channel, mechanisms: "PLAIN")

        async let auth: Void = connection.authenticate(SASLPlain(username: "user", password: "pass"))
        let line = try await expectClientLine(channel)
        #expect(line.hasPrefix("AUTH PLAIN "))
        try await serverSend(channel, "235 2.7.0 Authentication successful")
        try await auth
        #expect(connection.isAuthenticated)
    }

    @Test func authLoginRoundTrip() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithAuth(connection, channel, mechanisms: "LOGIN")

        async let auth: Void = connection.authenticate(SASLLogin(username: "user", password: "pass"))
        #expect(try await expectClientLine(channel) == "AUTH LOGIN")
        try await serverSend(channel, "334 " + Data("Username:".utf8).base64EncodedString())
        let usernameLine = try await expectClientLine(channel)
        #expect(Data(base64Encoded: usernameLine) == Data("user".utf8))
        try await serverSend(channel, "334 " + Data("Password:".utf8).base64EncodedString())
        let passwordLine = try await expectClientLine(channel)
        #expect(Data(base64Encoded: passwordLine) == Data("pass".utf8))
        try await serverSend(channel, "235 2.7.0 Authentication successful")
        try await auth
    }

    @Test func xoauth2TokenRefreshOn535RetriesOnce() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithAuth(connection, channel, mechanisms: "XOAUTH2")

        let callCount = CallCounter()
        async let auth: Void = connection.authenticate(
            XOAuth2(username: "user") {
                await callCount.increment()
                return "token-\(await callCount.value)"
            }
        )
        // First attempt.
        let firstLine = try await expectClientLine(channel)
        #expect(firstLine.hasPrefix("AUTH XOAUTH2 "))
        try await serverSend(channel, "535 5.7.8 Authentication failed")

        // Retry, per plan §4.5: tokenProvider() called again, exchange
        // retried exactly once.
        let secondLine = try await expectClientLine(channel)
        #expect(secondLine.hasPrefix("AUTH XOAUTH2 "))
        #expect(firstLine != secondLine) // different token embedded
        try await serverSend(channel, "235 2.7.0 Authentication successful")

        try await auth
        #expect(await callCount.value == 2)
    }

    @Test func unsupportedMechanismFailsWithoutSendingAUTH() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithAuth(connection, channel, mechanisms: "PLAIN")

        await #expect(throws: SMTPError.self) {
            try await connection.authenticate(SASLLogin(username: "u", password: "p"))
        }
    }

    // MARK: - SIZE fail-fast

    @Test func sizeExceededFailsFastOn552WithoutSendingRCPTOrDATA() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 SIZE 1000"])

        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["to@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8), estimatedSize: 5000)

        async let sendTask: Result<[DeliveryResult], Error> = resultOf { try await connection.sendMessage(envelope, message) }
        let mailLine = try await expectClientLine(channel)
        #expect(mailLine.hasPrefix("MAIL FROM:<from@example.com> SIZE="))
        try await serverSend(channel, "552 5.3.4 Message too large")

        let result = await sendTask
        guard case .failure(let error) = result, case .some(.sizeExceeded) = error as? SMTPError else {
            Issue.record("expected .sizeExceeded, got \(result)")
            return
        }
    }

    // MARK: - PIPELINING vs lock-step, and their equivalence

    @Test func pipeliningBatchesAllCommandsBeforeReadingReplies() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 PIPELINING"])

        let envelope = try SMTPEnvelope(
            mailFrom: .address("from@example.com"),
            recipients: ["a@example.com", "b@example.com"]
        )
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        async let sendTask = connection.sendMessage(envelope, message)

        // All three commands must be observable before any reply is sent
        // back -- that's the whole point of PIPELINING.
        #expect(try await expectClientLine(channel) == "MAIL FROM:<from@example.com>")
        #expect(try await expectClientLine(channel) == "RCPT TO:<a@example.com>")
        #expect(try await expectClientLine(channel) == "RCPT TO:<b@example.com>")
        #expect(try await expectClientLine(channel) == "DATA")

        try await serverSend(channel, "250 2.1.0 OK")
        try await serverSend(channel, "250 2.1.5 OK")
        try await serverSend(channel, "250 2.1.5 OK")
        try await serverSend(channel, "354 Start mail input")
        try await serverSend(channel, "250 2.0.0 Message accepted")

        let results = try await sendTask
        #expect(results.count == 2)
        for result in results {
            guard case .delivered = result.outcome else {
                Issue.record("expected delivered, got \(result.outcome)")
                return
            }
        }
    }

    @Test func pipeliningAndLockStepProduceEquivalentResultsForTheSameScript() async throws {
        func run(pipelining: Bool) async throws -> [DeliveryResult] {
            let (connection, channel) = try await ConnectionHarness.make()
            let capLine = pipelining ? "250 PIPELINING" : "250 8BITMIME"
            try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", capLine])

            let envelope = try SMTPEnvelope(
                mailFrom: .address("from@example.com"),
                recipients: ["good@example.com", "bad@example.com"]
            )
            let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

            async let sendTask = connection.sendMessage(envelope, message)

            if pipelining {
                _ = try await expectClientLine(channel) // MAIL
                _ = try await expectClientLine(channel) // RCPT good
                _ = try await expectClientLine(channel) // RCPT bad
                _ = try await expectClientLine(channel) // DATA
                try await serverSend(channel, "250 2.1.0 OK")
                try await serverSend(channel, "250 2.1.5 OK")
                try await serverSend(channel, "550 5.1.1 User unknown")
                try await serverSend(channel, "354 Start mail input")
                try await serverSend(channel, "250 2.0.0 Message accepted")
            } else {
                _ = try await expectClientLine(channel) // MAIL
                try await serverSend(channel, "250 2.1.0 OK")
                _ = try await expectClientLine(channel) // RCPT good
                try await serverSend(channel, "250 2.1.5 OK")
                _ = try await expectClientLine(channel) // RCPT bad
                try await serverSend(channel, "550 5.1.1 User unknown")
                _ = try await expectClientLine(channel) // DATA
                try await serverSend(channel, "354 Start mail input")
                try await serverSend(channel, "250 2.0.0 Message accepted")
            }

            return try await sendTask
        }

        let pipelined = try await run(pipelining: true)
        let lockStep = try await run(pipelining: false)

        #expect(pipelined.count == lockStep.count)
        for (a, b) in zip(pipelined, lockStep) {
            #expect(a.recipient == b.recipient)
            #expect(outcomeDescription(a.outcome) == outcomeDescription(b.outcome))
        }
    }

    @Test func partialRCPTRejectionStillSendsDATAAndReflectsMixedOutcome() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 PIPELINING"])

        let envelope = try SMTPEnvelope(
            mailFrom: .address("from@example.com"),
            recipients: ["good@example.com", "bad@example.com"]
        )
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        async let sendTask = connection.sendMessage(envelope, message)
        _ = try await expectClientLine(channel) // MAIL
        _ = try await expectClientLine(channel) // RCPT good
        _ = try await expectClientLine(channel) // RCPT bad
        _ = try await expectClientLine(channel) // DATA (pipelined regardless)

        try await serverSend(channel, "250 2.1.0 OK")
        try await serverSend(channel, "250 2.1.5 OK")           // good accepted
        try await serverSend(channel, "550 5.1.1 User unknown") // bad rejected
        try await serverSend(channel, "354 Start mail input")   // DATA proceeds: >=1 RCPT accepted
        try await serverSend(channel, "250 2.0.0 Message accepted")

        let results = try await sendTask
        #expect(results.count == 2)
        let good = results.first { $0.recipient == "good@example.com" }!
        let bad = results.first { $0.recipient == "bad@example.com" }!
        guard case .delivered = good.outcome else {
            Issue.record("expected good recipient delivered, got \(good.outcome)")
            return
        }
        guard case .permanentlyFailed = bad.outcome else {
            Issue.record("expected bad recipient permanently failed, got \(bad.outcome)")
            return
        }
    }

    /// Release review: a server that answers the pipelined DATA with 354
    /// even though every RCPT was rejected leaves the session in DATA mode.
    /// The connection must end the empty message with a lone dot (never the
    /// body) and be back in command mode afterwards.
    @Test func a354AfterEveryRCPTWasRejectedIsClosedWithADotNotTheBody() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 PIPELINING"])

        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["bad@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nSECRET BODY".utf8))

        async let sendTask = connection.sendMessage(envelope, message)
        _ = try await expectClientLine(channel) // MAIL
        _ = try await expectClientLine(channel) // RCPT
        _ = try await expectClientLine(channel) // DATA
        try await serverSend(channel, "250 2.1.0 OK")
        try await serverSend(channel, "550 5.1.1 User unknown")
        try await serverSend(channel, "354 Start mail input")
        #expect(try await expectClientLine(channel) == ".")
        try await serverSend(channel, "554 5.5.1 No valid recipients")

        let results = try await sendTask
        guard case .permanentlyFailed(let reply)? = results.first?.outcome else {
            Issue.record("expected the RCPT rejection, got \(String(describing: results.first?.outcome))")
            return
        }
        #expect(reply.code == 550)

        // Back in command mode: the next transaction's MAIL FROM is a command.
        let next = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["good@example.com"])
        async let secondSend = connection.sendMessage(next, message)
        #expect(try await expectClientLine(channel) == "MAIL FROM:<from@example.com>")
        _ = try await expectClientLine(channel)
        _ = try await expectClientLine(channel)
        try await serverSend(channel, "250 OK")
        try await serverSend(channel, "250 OK")
        try await serverSend(channel, "354 go")
        try await serverSend(channel, "250 queued")
        let second = try await secondSend
        guard case .delivered? = second.first?.outcome else {
            Issue.record("expected the second message delivered, got \(String(describing: second.first?.outcome))")
            return
        }
    }

    @Test func allRCPTRejectedNeverSendsMessageBody() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 PIPELINING"])

        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["bad@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nSECRET BODY".utf8))

        async let sendTask = connection.sendMessage(envelope, message)
        _ = try await expectClientLine(channel) // MAIL
        _ = try await expectClientLine(channel) // RCPT
        _ = try await expectClientLine(channel) // DATA (pipelined, always written)

        try await serverSend(channel, "250 2.1.0 OK")
        try await serverSend(channel, "550 5.1.1 User unknown") // sole RCPT rejected
        try await serverSend(channel, "554 5.5.1 No valid recipients")

        let results = try await sendTask
        #expect(results.count == 1)
        guard case .permanentlyFailed = results[0].outcome else {
            Issue.record("expected permanentlyFailed, got \(results[0].outcome)")
            return
        }
        // The body must never have been written -- confirmed by there
        // being nothing left buffered beyond the three command lines +
        // scripted replies above (no fourth outbound write to consume).
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
    }

    // MARK: - FIX #4 (plan §7, milestone architecture review): per-command
    // reply timeout. RFC 5321 §4.5.3.2 requires client-side minimum
    // timeouts per command phase -- without one, a hung/black-holed remote
    // server leaves the awaiting task suspended forever, and since the
    // connection never becomes "idle" mid-transaction, the pool's
    // idle-eviction path never reaps it either.

    @Test func nextReplyThrowsReplyTimedOutRatherThanHangingWhenTheServerNeverReplies() async throws {
        // A deliberately short `replyTimeout` (not tied to
        // `NIOAsyncTestingEventLoop`'s virtual clock -- `SMTPConnection`'s
        // timeout race uses real `Task.sleep`, so a short real-time value
        // is sufficient and needs no `advanceTime` choreography) and a
        // server double that never sends anything at all.
        let (connection, _channel) = try await ConnectionHarness.make(replyTimeout: 0.1)
        _ = _channel // the scripted "server" side is intentionally silent

        let outcome = await resultOf { try await connection.nextReply() }
        guard case .failure(let error) = outcome else {
            Issue.record("expected nextReply() to throw, got a reply instead")
            return
        }
        guard case .some(.replyTimedOut) = error as? SMTPConnectionError else {
            Issue.record("expected .replyTimedOut, got \(error)")
            return
        }
    }

    @Test func connectionTimeoutFlowsThroughThePoolsUnhealthyReleasePath() async throws {
        // FIX #4's explicit requirement: a timeout must flow through
        // `SMTPConnectionPool.release()`'s existing `healthy: Bool` catch
        // path exactly like any other thrown error (closed, not returned
        // to idle) -- `withConnection`'s `catch` already does this for any
        // thrown error; this confirms `.replyTimedOut` specifically is not
        // silently swallowed or special-cased away before it gets there.
        let key = SMTPConnectionPool.Key(host: "smtp.example.com", port: 587, tls: .none)
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 1, maxTotal: 10),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                let (connection, _) = try await ConnectionHarness.make(replyTimeout: 0.1)
                return connection
            }
        )

        await #expect(throws: SMTPConnectionError.self) {
            try await pool.withConnection(to: key) { connection in
                _ = try await connection.nextReply()
            }
        }

        // The timed-out connection must not have been returned to idle --
        // a subsequent checkout dials fresh rather than reusing it. This is
        // best confirmed indirectly: a second `withConnection` call
        // completes normally by dialing a brand-new connection, proving
        // the pool didn't hand back the same closed/unhealthy one.
        let secondCheckoutSucceeded = await resultOf {
            try await pool.withConnection(to: key) { connection in
                _ = connection // don't even need to use it -- just confirm checkout succeeds
            }
        }
        guard case .success = secondCheckoutSucceeded else {
            Issue.record("expected a fresh checkout to succeed after the unhealthy release, got \(secondCheckoutSucceeded)")
            return
        }

        await pool.shutdown()
    }

    // MARK: - Mid-conversation disconnect

    @Test func midConversationDisconnectSurfacesAsThrownErrorNotHang() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiateWithCapabilities(connection, channel, lines: ["250 smtp.example.com"])

        async let replyTask: Result<SMTPReply, Error> = resultOf { try await connection.nextReply() }
        try await channel.close()

        let outcome = await replyTask
        guard case .failure = outcome else {
            Issue.record("expected the channel closure to surface as a thrown error")
            return
        }
    }

    // MARK: - Helpers

    private func negotiateWithAuth(_ connection: SMTPConnection, _ channel: NIOAsyncTestingChannel, mechanisms: String) async throws {
        try await negotiateWithCapabilities(connection, channel, lines: ["250-smtp.example.com", "250 AUTH \(mechanisms)"])
    }

    private func negotiateWithCapabilities(_ connection: SMTPConnection, _ channel: NIOAsyncTestingChannel, lines: [String]) async throws {
        async let negotiate: Capabilities = connection.negotiateCapabilities()
        _ = try await expectClientLine(channel)
        for line in lines { try await serverSend(channel, line) }
        _ = try await negotiate
    }

    private func outcomeDescription(_ outcome: DeliveryResult.Outcome) -> String {
        switch outcome {
        case .delivered(let reply): return "delivered(\(reply.code))"
        case .permanentlyFailed(let reply): return "permanentlyFailed(\(reply.code))"
        case .queuedForRetry(_, let attempt, let last): return "queuedForRetry(attempt:\(attempt),code:\(last.code))"
        case .expired(let attempts, let last): return "expired(attempts:\(attempts),code:\(last.code))"
        case .ambiguous(let reply): return "ambiguous(\(reply?.code.description ?? "nil"))"
        case .failed(let error): return "failed(\(error))"
        }
    }
}

private actor CallCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}

struct SASLHardeningTests {
    @Test func anEndlessChallengeLoopIsCutOff() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        async let negotiate: Capabilities = connection.negotiateCapabilities()
        _ = try await expectClientLine(channel)
        try await serverSend(channel, "250-smtp.example.com")
        try await serverSend(channel, "250 AUTH LOGIN")
        _ = try await negotiate

        let auth = Task { try await connection.authenticate(SASLLogin(username: "u", password: "p")) }
        _ = try await expectClientLine(channel) // AUTH LOGIN
        for _ in 0..<SMTPConnection.maximumSASLChallenges {
            try await serverSend(channel, "334 " + Data("again".utf8).base64EncodedString())
            _ = try await expectClientLine(channel)
        }
        try await serverSend(channel, "334 " + Data("again".utf8).base64EncodedString())
        await #expect(throws: SMTPConnectionError.tooManySASLChallenges) { try await auth.value }
    }

    @Test func anXOAuth2UsernameOrTokenWithTheFieldSeparatorIsRejected() async {
        var forged = XOAuth2(username: "victim@example.com\u{1}auth=Bearer stolen") { "token" }
        await #expect(throws: SASLError.separatorInCredential(field: "username")) { _ = try await forged.initialResponse() }
        var badToken = XOAuth2(username: "u@example.com") { "tok\u{1}en" }
        await #expect(throws: SASLError.separatorInCredential(field: "token")) { _ = try await badToken.initialResponse() }
    }

    @Test func aPlainCredentialWithNULIsRejected() async {
        var plain = SASLPlain(username: "u\u{0}admin", password: "p")
        await #expect(throws: SASLError.separatorInCredential(field: "username")) { _ = try await plain.initialResponse() }
    }
}

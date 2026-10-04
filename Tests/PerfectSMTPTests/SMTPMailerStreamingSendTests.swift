//
//  SMTPMailerStreamingSendTests.swift
//  PerfectSMTPTests
//
//  Phase 5, Part 2: the `AsyncSequence`-based streaming `send<S>` overload
//  (Documentation/swift6-nio-rewrite-plan.md §4.9/§8). Mirrors
//  `SMTPMailerBatchFanoutTests.swift`'s counting-tracker style for the
//  array-based batch send, extended to also cover output-side backpressure
//  and cancellation, which the array-based overload has no equivalent of.
//

import Foundation
import Testing
@testable import PerfectSMTP

struct SMTPMailerStreamingSendTests {

    // MARK: - Input-side: sliding-window concurrency cap

    @Test func inFlightSendsNeverExceedConfiguredCap() async throws {
        let cap = 8
        let tracker = StreamingInFlightTracker()
        let transport = StreamingCountingTransport(tracker: tracker)
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: cap))

        let source = messageSequence(count: 250)

        var results: [DeliveryResult] = []
        for try await result in mailer.send(source, envelopeFrom: .address("bounce@example.com")) {
            results.append(result)
        }

        #expect(results.count == 250)
        #expect(await tracker.maxObserved <= cap)
        #expect(await tracker.maxObserved > 0) // sanity: fan-out actually happened concurrently
        #expect(await tracker.totalSends == 250)
    }

    // MARK: - Per-message error isolation

    @Test func oneMessageFailureDoesNotAbortTheStreamOrLoseOtherResults() async throws {
        let transport = StreamingSelectivelyFailingTransport(failingRecipient: "bad@example.com")
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: 8))

        let source = AsyncStream<EmailMessage> { continuation in
            for recipient in ["good1@example.com", "bad@example.com", "good2@example.com"] {
                var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
                message.to = [EmailAddress(address: recipient)]
                message.textBody = "hello"
                continuation.yield(message)
            }
            continuation.finish()
        }

        var results: [DeliveryResult] = []
        for try await result in mailer.send(source, envelopeFrom: .address("bounce@example.com")) {
            results.append(result)
        }

        // All three messages are represented -- the middle failure didn't
        // erase the other two, and the stream didn't terminate early.
        #expect(results.count == 3)

        let good1 = results.first { $0.recipient == "good1@example.com" }
        let good2 = results.first { $0.recipient == "good2@example.com" }
        let bad = results.first { $0.recipient == "bad@example.com" }

        guard let good1, case .delivered = good1.outcome else {
            Issue.record("expected good1@example.com delivered, got \(String(describing: good1?.outcome))")
            return
        }
        guard let good2, case .delivered = good2.outcome else {
            Issue.record("expected good2@example.com delivered, got \(String(describing: good2?.outcome))")
            return
        }
        guard let bad, case .failed = bad.outcome else {
            Issue.record("expected bad@example.com to surface as .failed, got \(String(describing: bad?.outcome))")
            return
        }
    }

    // MARK: - Output-side backpressure: production is throttled, not raced ahead

    @Test func productionStallsWhenTheOutputStreamIsNotBeingDrained() async throws {
        // A small cap so the bound is tight and easy to observe. The
        // transport completes essentially instantly (no artificial
        // per-send delay) -- if the streaming send had no real output-side
        // backpressure (e.g. the rejected `bufferingOldest`-only design),
        // `totalSends` would race up toward the full source size almost
        // immediately even though nothing is reading the returned stream.
        let cap = 4
        let totalMessages = 200
        let tracker = StreamingInFlightTracker()
        let transport = StreamingCountingTransport(tracker: tracker)
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: cap))

        let source = messageSequence(count: totalMessages)
        let stream = mailer.send(source, envelopeFrom: .address("bounce@example.com"))

        // Deliberately never touch `stream` for a while -- this is the
        // "consumer isn't draining" scenario the backpressure requirement
        // is about.
        try await Task.sleep(nanoseconds: UInt64(150) * 1_000_000)

        let stalledCount = await tracker.totalSends
        #expect(stalledCount < totalMessages)
        // Generous bound: the only "slack" beyond the sliding-window cap
        // itself is the `ResultChannel`'s own bounded capacity (also
        // `cap`), so total in-flight-or-buffered work should stay in the
        // same small ballpark as `cap`, nowhere near `totalMessages`.
        #expect(stalledCount <= cap * 4)

        // Now actually drain the stream and confirm production catches up
        // and every message is eventually accounted for -- proving nothing
        // was silently dropped while it was stalled.
        var results: [DeliveryResult] = []
        for try await result in stream {
            results.append(result)
        }
        #expect(results.count == totalMessages)
        #expect(await tracker.totalSends == totalMessages)
    }

    // MARK: - Regression: ResultChannel waiter state lost isolation

    /// Regression test for the `ResultChannel` isolation bug. The channel
    /// was an actor whose `push` re-parked in a loop from inside
    /// `withTaskCancellationHandler { withCheckedContinuation { ... } }`.
    /// Under Swift 6.4 in optimized builds, that continuation body ran off
    /// the actor's executor, so the process either aborted ("Incorrect actor
    /// executor assumption ... ResultChannel") or lost waiters, which
    /// dropped results or hung. A tiny channel, several results per message
    /// and a consumer that yields between reads keep every child task
    /// parking and re-parking in `push`, which is the path that broke.
    @Test(.timeLimit(.minutes(1)))
    func heavilyContendedStreamDeliversEveryResultExactlyOnce() async throws {
        let rounds = 20
        let messagesPerRound = 300
        let recipientsPerMessage = 3

        for round in 0..<rounds {
            let transport = StreamingCountingTransport(tracker: StreamingInFlightTracker())
            let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: 2))
            let source = AsyncStream<EmailMessage> { continuation in
                for i in 0..<messagesPerRound {
                    var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
                    message.to = (0..<recipientsPerMessage).map { EmailAddress(address: "r\(i)-\($0)@example.com") }
                    message.textBody = "hello \(i)"
                    continuation.yield(message)
                }
                continuation.finish()
            }

            var seen: [String: Int] = [:]
            for try await result in mailer.send(source, envelopeFrom: .address("bounce@example.com")) {
                seen[result.recipient, default: 0] += 1
                await Task.yield()
            }

            #expect(seen.count == messagesPerRound * recipientsPerMessage, "round \(round)")
            #expect(seen.values.allSatisfy { $0 == 1 }, "round \(round): a result was delivered more than once")
        }
    }

    // MARK: - Cancellation

    @Test func cancellingTheConsumingTaskStopsThePipelinePromptly() async throws {
        let cap = 4
        let tracker = StreamingInFlightTracker()
        // A per-send delay long enough that the test can reliably cancel
        // mid-flight and observe the count stop changing afterward.
        let transport = StreamingCountingTransport(tracker: tracker, perSendDelay: 0.020)
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: cap))

        let source = messageSequence(count: 100_000)

        let consumer = Task {
            for try await _ in mailer.send(source, envelopeFrom: .address("bounce@example.com")) {
                // Consume as fast as produced.
            }
        }

        // Let a handful of sends actually happen, then cancel.
        try await Task.sleep(nanoseconds: UInt64(60) * 1_000_000)
        consumer.cancel()

        // Give the cancellation-aware pipeline a moment to actually wind
        // down (in-flight sends complete, `startNextIfPossible` stops
        // advancing the source iterator).
        try await Task.sleep(nanoseconds: UInt64(100) * 1_000_000)
        let countShortlyAfterCancel = await tracker.totalSends

        try await Task.sleep(nanoseconds: UInt64(200) * 1_000_000)
        let countMuchLaterAfterCancel = await tracker.totalSends

        // The defining assertion: production stopped -- it did not keep
        // marching toward 100,000 in the background after cancellation.
        #expect(countMuchLaterAfterCancel == countShortlyAfterCancel)
        #expect(countMuchLaterAfterCancel < 100_000)
    }

    @Test func abandoningTheStreamWithoutDrainingStopsThePipelinePromptly() async throws {
        // No `Task` cancellation at all here -- the stream is simply never
        // iterated. This exercises the `StreamLifetimeToken` deinit path
        // (the "torn down without being drained" case), distinct from the
        // task-cancellation path above.
        let cap = 4
        let tracker = StreamingInFlightTracker()
        let transport = StreamingCountingTransport(tracker: tracker, perSendDelay: 0.020)
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: cap))

        let source = messageSequence(count: 100_000)

        do {
            _ = mailer.send(source, envelopeFrom: .address("bounce@example.com"))
            // `stream` goes out of scope here at the end of this `do`
            // block, with no reference kept and no iteration ever
            // performed -- the `unfolding` closure (and its
            // `StreamLifetimeToken`) should be released shortly after.
        }

        try await Task.sleep(nanoseconds: UInt64(150) * 1_000_000)
        let countShortlyAfter = await tracker.totalSends

        try await Task.sleep(nanoseconds: UInt64(200) * 1_000_000)
        let countMuchLaterAfter = await tracker.totalSends

        #expect(countMuchLaterAfter == countShortlyAfter)
        #expect(countMuchLaterAfter < 100_000)
    }
}

// MARK: - Shared test fixtures

private func messageSequence(count: Int) -> AsyncStream<EmailMessage> {
    AsyncStream { continuation in
        for i in 0..<count {
            var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
            message.to = [EmailAddress(address: "user\(i)@example.com")]
            message.textBody = "hello \(i)"
            continuation.yield(message)
        }
        continuation.finish()
    }
}

private actor StreamingInFlightTracker {
    private(set) var current = 0
    private(set) var maxObserved = 0
    private(set) var totalSends = 0

    func enter() {
        current += 1
        maxObserved = max(maxObserved, current)
        totalSends += 1
    }

    func exit() {
        current -= 1
    }
}

/// A `SMTPTransport` that simulates network latency (a short, optional
/// sleep) around a counter increment/decrement, so the fan-out's actual
/// concurrency and pacing are observable without a real connection pool or
/// socket.
private struct StreamingCountingTransport: SMTPTransport {
    let tracker: StreamingInFlightTracker
    var perSendDelay: TimeInterval = 0

    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        await tracker.enter()
        if perSendDelay > 0 {
            do {
                try await Task.sleep(nanoseconds: UInt64(perSendDelay * 1_000_000_000))
            } catch {
                await tracker.exit()
                throw error
            }
        }
        await tracker.exit()
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"])))
        }
    }
}

/// A `SMTPTransport` that throws a plain transport-level error (not a
/// per-recipient `DeliveryResult` rejection) whenever the envelope's
/// recipients include `failingRecipient`, and otherwise succeeds normally.
private struct StreamingSelectivelyFailingTransport: SMTPTransport {
    struct SimulatedTransportFailure: Error, Sendable {}

    let failingRecipient: String

    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        guard !envelope.recipients.contains(failingRecipient) else {
            throw SimulatedTransportFailure()
        }
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"])))
        }
    }
}

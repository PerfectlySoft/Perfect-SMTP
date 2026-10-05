//
//  DirectMXRetryQueueTests.swift
//  PerfectSMTPTests
//
//  Plan §4.8 / this task's required coverage list: 421 vs. 450/451/452 get
//  different, actually-configured backoff durations; an entry retried past
//  the max-attempt cap or max-age becomes `.expired`, not stuck retrying
//  forever or silently dropped; `shutdown()` cancels the background loop
//  cleanly (no hang, no crash) -- mirroring `SMTPConnectionPoolTests`'
//  pattern for testing pool shutdown from Phase 1.
//

import Foundation
import Testing
@testable import PerfectSMTP

struct DirectMXRetryQueueTests {
    // MARK: - 421 vs. greylist vs. other 4yz backoff durations

    @Test func classifyAppliesTheExactConfiguredBackoffPerReplyClass() {
        let policy = RetryBackoffPolicy(
            serviceUnavailable: 111,
            greylist: 22,
            defaultTransient: 3
        )
        let reply421 = SMTPReply(code: 421, lines: ["4.3.2 Service unavailable, closing channel"])
        let reply450 = SMTPReply(code: 450, lines: ["4.2.0 Greylisted, try again later"])
        let reply451 = SMTPReply(code: 451, lines: ["4.3.0 Local error"])
        let reply452 = SMTPReply(code: 452, lines: ["4.2.2 Mailbox full"])
        let reply441 = SMTPReply(code: 441, lines: ["4.4.1 Some other transient condition"])

        let before = Date()
        let outcome421 = policy.classify(reply421, attempt: 1)
        let outcome450 = policy.classify(reply450, attempt: 1)
        let outcome451 = policy.classify(reply451, attempt: 1)
        let outcome452 = policy.classify(reply452, attempt: 1)
        let outcome441 = policy.classify(reply441, attempt: 1)

        #expect(isApproximately(backoffSeconds(outcome421, since: before), 111))
        #expect(isApproximately(backoffSeconds(outcome450, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome451, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome452, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome441, since: before), 3))

        // Explicitly not just "these differ" -- 421 must be the *longest*
        // backoff (plan §4.8's 421-vs-greylist correction: retrying an
        // overloaded receiver quickly worsens the overload).
        #expect(backoffSeconds(outcome421, since: before) > backoffSeconds(outcome450, since: before))
        #expect(backoffSeconds(outcome450, since: before) > backoffSeconds(outcome441, since: before))
    }

    @Test func aPermanentReplyIsNeverBackedOffEvenWithAConfiguredPolicy() {
        let policy = RetryBackoffPolicy(serviceUnavailable: 999, greylist: 999, defaultTransient: 999)
        let reply550 = SMTPReply(code: 550, lines: ["5.1.1 User unknown"])
        guard case .permanentlyFailed = policy.classify(reply550, attempt: 1) else {
            Issue.record("expected .permanentlyFailed for a 5yz reply regardless of policy")
            return
        }
    }

    // MARK: - Retry ceiling: max attempts

    @Test func exceedingMaxAttemptsBecomesExpiredNotStuckForever() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: 0.005, greylist: 0.005, defaultTransient: 0.005),
            maxAttempts: 2,
            maxAge: 3600 // effectively disabled for this test -- only the attempt cap should trigger
        )
        // Always comes back greylisted -- a destination that never
        // recovers, the exact scenario the attempt cap exists for.
        let redeliverCalls = CallCountBox()
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                await redeliverCalls.increment()
                let reply = SMTPReply(code: 450, lines: ["4.2.0 still greylisted"])
                // The `attempt` value returned here is deliberately wrong
                // (always 1) -- exactly like every real classification
                // site in this codebase (`SMTPConnection.outcomeFor`,
                // `DirectMXTransport.classify(smtpError:)`), none of which
                // have any memory of retry history. This is precisely what
                // `DirectMXRetryQueue.handle(results:entry:)` must not
                // trust -- it tracks the real attempt count itself.
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst()
        guard case .expired(let attempts, _) = terminal.outcome else {
            Issue.record("expected .expired once the attempt cap is exceeded, got \(terminal.outcome)")
            return
        }
        #expect(attempts > config.maxAttempts)
        // The entry must actually have been retried -- not dropped after
        // the very first failure.
        #expect(await redeliverCalls.count >= 1)

        await queue.shutdown()
    }

    // MARK: - Retry ceiling: max age

    @Test func exceedingMaxAgeBecomesExpiredEvenWithAttemptsRemaining() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: 0.005, greylist: 0.005, defaultTransient: 0.005),
            maxAttempts: 1000, // effectively disabled -- only maxAge should trigger
            maxAge: 0.03
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                let reply = SMTPReply(code: 450, lines: ["4.2.0 still greylisted"])
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst(timeoutSeconds: 3)
        guard case .expired = terminal.outcome else {
            Issue.record("expected .expired once maxAge elapses, got \(terminal.outcome)")
            return
        }

        await queue.shutdown()
    }

    // MARK: - `.ambiguous` (and every other non-`.queuedForRetry` outcome) is never enqueued

    @Test func enqueueIsANoOpForEveryNonQueuedForRetryOutcome() async throws {
        let queue = DirectMXRetryQueue(configuration: .init(), redeliver: { envelope, _ in
            envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
        })
        let reply = SMTPReply(code: 550, lines: ["5.1.1 rejected"])
        let message = DirectMXRetryQueueTests.message()

        let ambiguousAccepted = await queue.enqueue(recipients: ["a@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .ambiguous(nil))
        let deliveredAccepted = await queue.enqueue(recipients: ["b@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .delivered(reply))
        let permanentAccepted = await queue.enqueue(recipients: ["c@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .permanentlyFailed(reply))
        let expiredAccepted = await queue.enqueue(recipients: ["d@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .expired(attempts: 5, last: reply))

        #expect(!ambiguousAccepted)
        #expect(!deliveredAccepted)
        #expect(!permanentAccepted)
        #expect(!expiredAccepted)
        #expect(await queue.pendingEntriesSnapshot().isEmpty)

        await queue.shutdown()
    }

    // MARK: - FIX #6 (LOW-MEDIUM security, milestone security review): a
    // hard cap on total pending entries.

    @Test func enqueueAtCapacityReportsFailedRatherThanGrowingUnbounded() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            // A backoff far enough in the future that nothing enqueued
            // below is ever redelivered during this test -- the point is
            // to observe `enqueue`'s own immediate capacity check, not the
            // background loop.
            backoff: .init(serviceUnavailable: 3600, greylist: 3600, defaultTransient: 3600),
            maxAttempts: 10, maxAge: 3600,
            maxTotalEntries: 3
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        func enqueueOne(_ recipient: String) async -> Bool {
            await queue.enqueue(
                recipients: [recipient], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
                outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(3600), attempt: 1, last: reply)
            )
        }

        // Fill the queue to exactly `maxTotalEntries` (3) -- all three must be accepted.
        #expect(await enqueueOne("a@example.com"))
        #expect(await enqueueOne("b@example.com"))
        #expect(await enqueueOne("c@example.com"))
        #expect(await queue.pendingEntriesSnapshot().count == 3)

        // The fourth must be rejected immediately -- not silently dropped
        // (it's reported via `onTerminalOutcome`, distinctly, as `.failed`)
        // and not grown past the cap (`entries.count` stays at 3).
        let fourthAccepted = await enqueueOne("d@example.com")
        #expect(!fourthAccepted)
        #expect(await queue.pendingEntriesSnapshot().count == 3)

        let terminal = try await collector.waitForFirst()
        #expect(terminal.recipient == "d@example.com")
        guard case .failed(let error) = terminal.outcome, let queueError = error as? DirectMXRetryQueueError,
              case .queueAtCapacity(let maxTotalEntries) = queueError
        else {
            Issue.record("expected .failed(.queueAtCapacity), got \(terminal.outcome)")
            return
        }
        #expect(maxTotalEntries == 3)

        await queue.shutdown()
    }

    // MARK: - Lifecycle: shutdown cancels the background loop cleanly

    @Test func shutdownCancelsTheBackgroundLoopCleanlyAndReportsStillPendingEntries() async throws {
        let collector = OutcomeCollector()
        let redeliverCalls = CallCountBox()
        let queue = DirectMXRetryQueue(
            configuration: .init(backoff: .init(serviceUnavailable: 3600, greylist: 3600, defaultTransient: 3600)),
            redeliver: { envelope, _ in
                await redeliverCalls.increment()
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        // Scheduled far in the future -- guaranteed to still be pending
        // (never redelivered) when `shutdown()` runs below.
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["stuck@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(3600), attempt: 1, last: reply)
        )
        #expect(await queue.pendingEntriesSnapshot().count == 1)

        // `shutdown()` itself must return promptly -- no hang -- and must
        // not crash regardless of whether the background loop happened to
        // be asleep (the common case here) or mid-iteration.
        await queue.shutdown()

        // Never redelivered -- the loop was genuinely cancelled, not
        // allowed to fire once more before stopping.
        #expect(await redeliverCalls.count == 0)

        // The still-pending entry is reported as terminal (`.failed`,
        // wrapping `DirectMXRetryQueueError.shutdownWhilePending`) rather
        // than silently discarded -- this queue's documented shutdown
        // decision (see `DirectMXRetryQueue.shutdown()`'s doc comment).
        let terminal = try await collector.waitForFirst()
        #expect(terminal.recipient == "stuck@example.com")
        guard case .failed(let error) = terminal.outcome, let queueError = error as? DirectMXRetryQueueError,
              case .shutdownWhilePending = queueError
        else {
            Issue.record("expected .failed(.shutdownWhilePending), got \(terminal.outcome)")
            return
        }

        // A second `shutdown()` call must not hang or crash either.
        await queue.shutdown()
        // Calling `enqueue` after shutdown is a documented no-op, not a crash.
        let acceptedAfterShutdown = await queue.enqueue(
            recipients: ["late@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
        )
        #expect(!acceptedAfterShutdown)
    }

    // MARK: - Happy path: a rescheduled entry that eventually succeeds is reported `.delivered`

    @Test func aRescheduledEntryThatEventuallySucceedsReportsDelivered() async throws {
        let collector = OutcomeCollector()
        let attemptsSoFar = CallCountBox()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: 0.005, greylist: 0.005, defaultTransient: 0.005),
            maxAttempts: 10, maxAge: 3600
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                await attemptsSoFar.increment()
                let n = await attemptsSoFar.count
                if n < 2 {
                    let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
                    return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
                }
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst()
        guard case .delivered = terminal.outcome else {
            Issue.record("expected .delivered once the destination recovers, got \(terminal.outcome)")
            return
        }
        #expect(await attemptsSoFar.count == 2)

        await queue.shutdown()
    }

    // MARK: - FIX #3 (concurrency + SMTP-protocol reviews): a nudge-
    // triggered cancel-and-restart must not leak the superseded loop task
    // as a permanent duplicate. Every other test in this file enqueues
    // only one entry, so none of them exercise this branch at all --
    // `nudgeLoop`'s cancel-and-restart path only runs when a *second*
    // entry arrives with an earlier `nextAttempt` while the loop is
    // already asleep on an earlier-enqueued, later-due entry.

    @Test func nudgeRestartCancelsThePreviousLoopTaskInsteadOfLeakingAZombie() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: 0.001, greylist: 0.001, defaultTransient: 0.001),
            maxAttempts: 10, maxAge: 3600
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        // Entry 1: due comfortably later -- this is what starts the loop
        // task sleeping on a target that the second enqueue below must
        // then notice is stale.
        await queue.enqueue(
            recipients: ["slow@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(0.4), attempt: 1, last: reply)
        )
        // Give the loop time to actually start sleeping on entry 1's
        // target before nudging it.
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000)
        // Entry 2: due much sooner than entry 1's `nextAttempt` -- forces
        // `nudgeLoop`'s cancel-and-restart branch (not just the
        // fresh-start branch every other test in this file exercises).
        await queue.enqueue(
            recipients: ["fast@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(0.05), attempt: 1, last: reply)
        )

        let first = try await collector.waitForFirst(timeoutSeconds: 3)
        let second = try await collector.waitForFirst(timeoutSeconds: 3)
        #expect(Set([first.recipient, second.recipient]) == Set(["fast@example.com", "slow@example.com"]))
        guard case .delivered = first.outcome, case .delivered = second.outcome else {
            Issue.record("expected both entries to resolve .delivered, got \(first.outcome) and \(second.outcome)")
            return
        }

        // The decisive assertion (this is the regression coverage for the
        // zombie-task leak itself, not just "both entries eventually
        // resolved," which would pass even with a leaked duplicate loop
        // since `entries`' remove-before-`await` discipline already
        // prevents double-*redelivery* -- the bug is a leaked *task*, not
        // corrupted delivery): no `processDueEntries()` pass ever ran on a
        // superseded loop task. Before the fix, the cancelled-but-not-
        // exited old loop task fell through its own `catch` and called
        // `processDueEntries()` right away (its cancelled sleep resumes
        // immediately), then kept running as an independent duplicate. A
        // duplicate that was never cancelled at all counts here too.
        //
        // This used to assert exactly two passes in total, which flaked
        // under heavy load on Linux (5/40 loaded full-suite runs). The
        // total is timing-dependent: a scheduler starved past entry 1's
        // due time folds both entries into one pass, and since the loop
        // sleeps on the monotonic clock but judges "due" by `Date()`, a
        // wall clock step can wake it early for a harmless extra pass.
        // Neither is the zombie, so the total isn't asserted.
        #expect(await queue.processDueEntriesFromSupersededLoopCountForTesting == 0)

        await queue.shutdown()
    }

    // A nudge's superseded loop task resumes from its cancelled sleep at
    // some point after the replacement has started. It must not touch
    // `currentSleepTarget` on its way out: if it clears the replacement's
    // target, the next earlier-due entry sees "not sleeping" and skips the
    // nudge, so it waits for the replacement's later wake instead of being
    // tried on time.
    @Test func aSupersededLoopTaskDoesNotClearItsReplacementsSleepTarget() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: 60, greylist: 60, defaultTransient: 60),
            maxAttempts: 10, maxAge: 3600
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        func enqueue(_ recipient: String, dueIn seconds: TimeInterval) async {
            await queue.enqueue(
                recipients: [recipient], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
                outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(seconds), attempt: 1, last: reply)
            )
        }

        // A starts the loop; B nudges it, so the first loop task is
        // cancelled and a replacement sleeps until B is due.
        await enqueue("a@example.com", dueIn: 30)
        try await Task.sleep(nanoseconds: 20 * 1_000_000)
        await enqueue("b@example.com", dueIn: 10)
        // Give both loop tasks time to settle: the replacement asleep on
        // B, the superseded one (most likely) resumed from its cancelled
        // sleep and gone.
        try await Task.sleep(nanoseconds: 100 * 1_000_000)
        // C is due well before B, so it has to nudge the replacement.
        let cEnqueued = ContinuousClock.now
        await enqueue("c@example.com", dueIn: 0.05)

        let first = try await collector.waitForFirst(timeoutSeconds: 20)
        let elapsed = ContinuousClock.now - cEnqueued
        #expect(first.recipient == "c@example.com")
        // Generous for a loaded CI box; the failure mode waits ~10s for B.
        #expect(elapsed < .seconds(3), "C took \(elapsed); the nudge was skipped")

        await queue.shutdown()
    }

    // The loop exits when the queue empties. It has to clear `loopTask` as
    // it goes, or `nudgeLoop` (which only starts a loop when `loopTask` is
    // nil) never starts another, and nothing enqueued after the first
    // drain is retried until `shutdown()` reports it as failed.
    @Test func anEntryEnqueuedAfterTheQueueDrainsIsStillRetried() async throws {
        let collector = OutcomeCollector()
        let queue = DirectMXRetryQueue(
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        func enqueue(_ recipient: String) async {
            await queue.enqueue(
                recipients: [recipient], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
                outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
            )
        }

        await enqueue("first@example.com")
        let first = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(first.recipient == "first@example.com")
        // Let the loop find the queue empty and exit.
        try await Task.sleep(nanoseconds: 100 * 1_000_000)

        await enqueue("second@example.com")
        let second = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(second.recipient == "second@example.com")
        guard case .delivered = second.outcome else {
            Issue.record("expected the second entry to be retried and delivered, got \(second.outcome)")
            return
        }

        await queue.shutdown()
    }

    // `shutdown()` drains `entries`, but an entry whose `redeliver` is in
    // flight isn't in `entries` at that moment. If that attempt comes back
    // transient, it must be reported as `.shutdownWhilePending` rather
    // than quietly put back into a queue that will never run again.
    @Test func aRetryInFlightDuringShutdownIsReportedNotSilentlyRequeued() async throws {
        let collector = OutcomeCollector()
        let (entered, enteredContinuation) = AsyncStream<Void>.makeStream()
        let (release, releaseContinuation) = AsyncStream<Void>.makeStream()
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        let queue = DirectMXRetryQueue(
            redeliver: { envelope, _ in
                enteredContinuation.yield()
                for await _ in release { break }
                return envelope.recipients.map {
                    DeliveryResult(recipient: $0, outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply))
                }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )
        await queue.enqueue(
            recipients: ["inflight@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
        )
        for await _ in entered { break }
        await queue.shutdown()
        releaseContinuation.yield()

        let result = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(result.recipient == "inflight@example.com")
        guard case .failed(let error) = result.outcome,
              case .shutdownWhilePending(let attempt, _)? = error as? DirectMXRetryQueueError else {
            Issue.record("expected .failed(.shutdownWhilePending), got \(result.outcome)")
            return
        }
        #expect(attempt == 2)
        #expect(await queue.pendingEntriesSnapshot().isEmpty)
    }

    private static func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))
    }
}

private func isApproximately(_ lhs: Double, _ rhs: Double) -> Bool { abs(lhs - rhs) < 1.0 }

private func backoffSeconds(_ outcome: DeliveryResult.Outcome, since: Date) -> Double {
    guard case .queuedForRetry(let nextAttempt, _, _) = outcome else {
        Issue.record("expected .queuedForRetry, got \(outcome)")
        return -1
    }
    return nextAttempt.timeIntervalSince(since)
}

/// Collects every `DeliveryResult` reported via a `DirectMXRetryQueue`'s
/// `onTerminalOutcome` callback, and lets a test await the first one
/// (bounded, polling) without a fixed `Task.sleep` guess.
actor OutcomeCollector {
    private var results: [DeliveryResult] = []
    private var waiters: [(id: UUID, continuation: CheckedContinuation<DeliveryResult, Error>)] = []
    private var expired: Set<UUID> = []

    func record(_ result: DeliveryResult) {
        if !waiters.isEmpty {
            waiters.removeFirst().continuation.resume(returning: result)
        } else {
            results.append(result)
        }
    }

    /// Bounded wait for the first recorded outcome -- resumes immediately
    /// if one is already recorded, otherwise parks until `record(_:)`
    /// delivers one or `timeoutSeconds` elapses. On timeout the parked
    /// waiter is removed and resumed with `.timedOut`, so a result that
    /// never arrives fails the test instead of hanging it, and a late
    /// result goes to the next wait rather than to an abandoned one.
    func waitForFirst(timeoutSeconds: Double = 2) async throws -> DeliveryResult {
        if !results.isEmpty { return results.removeFirst() }
        let id = UUID()
        let timeout = Task {
            try await Task.sleep(nanoseconds: UInt64(max(0, timeoutSeconds) * 1_000_000_000))
            await self.expire(id)
        }
        defer { timeout.cancel() }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<DeliveryResult, Error>) in
            Task { await self.park(id, continuation) }
        }
    }

    private func park(_ id: UUID, _ continuation: CheckedContinuation<DeliveryResult, Error>) {
        if expired.remove(id) != nil {
            continuation.resume(throwing: OutcomeCollectorError.timedOut)
        } else if !results.isEmpty {
            continuation.resume(returning: results.removeFirst())
        } else {
            waiters.append((id, continuation))
        }
    }

    private func expire(_ id: UUID) {
        if let index = waiters.firstIndex(where: { $0.id == id }) {
            waiters.remove(at: index).continuation.resume(throwing: OutcomeCollectorError.timedOut)
        } else {
            // Not parked yet; `park` will see this and fail the wait.
            expired.insert(id)
        }
    }
}

private enum OutcomeCollectorError: Error {
    case timedOut
}

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

    // MARK: - The loop must restart after the queue drains

    @Test(.timeLimit(.minutes(1)))
    func anEntryEnqueuedAfterTheQueueDrainsIsStillRetried() async throws {
        // The loop task exits once `entries` is empty. A later enqueue has
        // to start a new one; otherwise that entry sits in the queue,
        // never retried, until `shutdown()`.
        let collector = OutcomeCollector()
        let queue = DirectMXRetryQueue(
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])

        await queue.enqueue(
            recipients: ["first@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
        )
        let first = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(first.recipient == "first@example.com")

        // Wait until the first loop has run out of work and exited (not
        // just until the entry left `entries`, which happens before the
        // loop finishes) -- otherwise the still-running loop would pick up
        // the next entry and the test would stop covering the bug.
        try await waitUntil { await queue.liveLoopCountForTesting == 0 }

        await queue.enqueue(
            recipients: ["second@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
        )
        let second = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(second.recipient == "second@example.com")
        guard case .delivered = second.outcome else {
            Issue.record("expected the second entry to be redelivered, got \(second.outcome)")
            return
        }
        await queue.shutdown()
    }

    // MARK: - FIX #3 (concurrency + SMTP-protocol reviews): a nudge-
    // triggered cancel-and-restart must not leak the superseded loop task
    // as a permanent duplicate. Every other test in this file enqueues
    // only one entry, so none of them exercise this branch at all --
    // `nudgeLoop`'s cancel-and-restart path only runs when a *second*
    // entry arrives with an earlier `nextAttempt` while the loop is
    // already asleep on an earlier-enqueued, later-due entry.

    @Test(.timeLimit(.minutes(1)))
    func nudgeRestartCancelsThePreviousLoopTaskInsteadOfLeakingAZombie() async throws {
        let collector = OutcomeCollector()
        let queue = DirectMXRetryQueue(
            redeliver: { envelope, _ in
                envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])

        // Entry 1: due far beyond this test, so the loop sleeps on it
        // throughout and no timing assumption is involved.
        await queue.enqueue(
            recipients: ["slow@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(30), attempt: 1, last: reply)
        )
        try await waitUntil { await queue.isLoopSleepingForTesting }

        // Entry 2: due much sooner than entry 1's `nextAttempt` -- forces
        // `nudgeLoop`'s cancel-and-restart branch (not just the
        // fresh-start branch every other test in this file exercises).
        await queue.enqueue(
            recipients: ["fast@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(0.05), attempt: 1, last: reply)
        )
        #expect(await queue.loopRestartCountForTesting == 1, "the cancel-and-restart branch didn't run")

        let fast = try await collector.waitForFirst(timeoutSeconds: 5)
        #expect(fast.recipient == "fast@example.com")
        guard case .delivered = fast.outcome else {
            Issue.record("expected fast@example.com to be redelivered, got \(fast.outcome)")
            return
        }

        // The decisive assertions (regression coverage for the zombie-task
        // leak itself, not just "the entry got delivered", which would
        // pass even with a leaked duplicate loop, since `entries`' remove-
        // before-`await` discipline already prevents double redelivery).
        // Before the fix, the superseded loop task fell through its
        // `catch`, called `processDueEntries()` right away and kept running
        // as an independent duplicate. Now exactly one loop task survives
        // (the replacement, asleep on entry 1) and no superseded one ever
        // processed entries. Counting live loops also catches a superseded
        // loop that was never cancelled at all, which would sleep on
        // entry 1's 30 s target without calling anything.
        let oneLoopLeft = try? await waitUntil(timeoutSeconds: 2) { await queue.liveLoopCountForTesting == 1 }
        let liveLoops = await queue.liveLoopCountForTesting
        #expect(oneLoopLeft != nil, "\(liveLoops) loop tasks still running after the restart")
        #expect(await queue.processDueEntriesFromSupersededLoopCountForTesting == 0)
        #expect(await queue.pendingEntriesSnapshot().map(\.recipients) == [["slow@example.com"]])

        await queue.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func aSupersededLoopDoesNotHideTheReplacementsSleepTarget() async throws {
        // After a restart, the superseded loop wakes from its cancelled
        // sleep at about the same time the replacement goes to sleep. It
        // used to clear `currentSleepTarget` on its way out; when that
        // happened after the replacement was asleep, the actor believed
        // nothing was sleeping, so an earlier-due entry enqueued next
        // didn't trigger a restart and waited for the stale target. Which
        // side runs first depends on scheduling, so this runs many queues
        // at once to get both orders, and checks the invariant directly.
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        let failures = try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<40 {
                group.addTask {
                    let collector = OutcomeCollector()
                    let queue = DirectMXRetryQueue(
                        redeliver: { envelope, _ in
                            envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
                        },
                        onTerminalOutcome: { result in await collector.record(result) }
                    )
                    func enqueue(_ recipient: String, dueIn seconds: TimeInterval) async {
                        await queue.enqueue(
                            recipients: [recipient], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
                            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(seconds), attempt: 1, last: reply)
                        )
                    }

                    await enqueue("a@example.com", dueIn: 20)
                    try await waitUntil { await queue.isLoopSleepingForTesting }
                    await enqueue("b@example.com", dueIn: 10)
                    try await waitUntil { await queue.liveLoopCountForTesting == 1 }
                    try await Task.sleep(nanoseconds: 5_000_000)
                    // The replacement is asleep on b's target; the actor
                    // must still know that.
                    guard await queue.isLoopSleepingForTesting else {
                        await queue.shutdown()
                        return 1
                    }
                    await enqueue("c@example.com", dueIn: 0.01)
                    let earliest = try await collector.waitForFirst(timeoutSeconds: 3)
                    await queue.shutdown()
                    return earliest.recipient == "c@example.com" ? 0 : 1
                }
            }
            return try await group.reduce(0, +)
        }
        #expect(failures == 0, "\(failures) of 40 queues lost track of their sleeping loop")
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

/// Polls `condition` every millisecond until it holds, throwing
/// `OutcomeCollectorError.timedOut` after `timeoutSeconds`.
private func waitUntil(timeoutSeconds: Double = 5, _ condition: () async -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while await !condition() {
        guard Date() < deadline else { throw OutcomeCollectorError.timedOut }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
}

/// Collects every `DeliveryResult` reported via a `DirectMXRetryQueue`'s
/// `onTerminalOutcome` callback, and lets a test await the first one
/// (bounded, polling) without a fixed `Task.sleep` guess.
actor OutcomeCollector {
    private var results: [DeliveryResult] = []

    func record(_ result: DeliveryResult) {
        results.append(result)
    }

    /// Bounded wait for the first recorded outcome: returns it as soon as
    /// one is recorded, or throws `timedOut` after `timeoutSeconds`. Polls,
    /// so the timeout always fires. (The previous version parked a
    /// continuation inside a task group; that child ignored cancellation,
    /// so the group could never return on timeout and a lost delivery hung
    /// the test run instead of failing it.)
    func waitForFirst(timeoutSeconds: Double = 2) async throws -> DeliveryResult {
        let deadline = Date().addingTimeInterval(max(0, timeoutSeconds))
        while results.isEmpty {
            guard Date() < deadline else { throw OutcomeCollectorError.timedOut }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        return results.removeFirst()
    }
}

private enum OutcomeCollectorError: Error {
    case timedOut
}

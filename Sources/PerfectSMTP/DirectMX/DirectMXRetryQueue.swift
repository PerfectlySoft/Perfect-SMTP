//
//  DirectMXRetryQueue.swift
//  PerfectSMTP
//
//  Plan §4.8/§9 Phase 3: the retry-queue actor Phase 1 explicitly deferred
//  (`SMTPConnection.outcomeFor`'s doc comment: "Phase 1's job is correct
//  single-attempt classification, not a full retry scheduler... the actual
//  scheduling/execution of retries is Phase 3 territory"). This actor is
//  that scheduler: it holds pending `.queuedForRetry` entries, wakes on its
//  own internal timer to redrive due ones, applies the corrected
//  421-vs-greylist backoff distinction (now genuinely configurable, not
//  Phase 1's hardcoded placeholders), and enforces the retry
//  ceiling/expiry the plan required but left unspecified.
//
//  Scope boundary -- in-memory only, deliberately (stated explicitly per
//  this task's instructions, not silently omitted): this is a library, not
//  a standalone daemon. Every `Entry` lives only in this actor's own
//  `entries` dictionary, for the lifetime of the process. A caller wanting
//  durable retry-queue persistence across process restarts (so an
//  in-flight retry isn't silently lost on a crash/deploy) must build that
//  themselves on top of this API -- e.g. by observing `onTerminalOutcome`
//  and `pendingEntriesSnapshot()` and persisting/restoring entries
//  externally. Nothing here reads or writes disk, a database, or any other
//  durable store.
//

import Foundation

/// Errors specific to this actor's own bookkeeping (as opposed to
/// `SMTPError`, which classifies SMTP-level replies, or `DirectMXError`,
/// which classifies MX-resolution/host-fallback failures).
public enum DirectMXRetryQueueError: Error, Sendable, Equatable {
    /// `shutdown()` ran while this recipient still had a pending,
    /// not-yet-resolved retry entry -- see `shutdown()`'s doc comment for
    /// why this is surfaced rather than silently dropped.
    case shutdownWhilePending(attempt: Int, last: SMTPReply)
    /// FIX #6 (LOW-MEDIUM security, milestone security review): `enqueue`
    /// was called while this queue already held
    /// `Configuration.maxTotalEntries` pending entries -- the new entry is
    /// reported as this terminal `.failed` outcome immediately rather than
    /// silently dropped or grown past the configured cap. See
    /// `Configuration.maxTotalEntries`'s doc comment.
    case queueAtCapacity(maxTotalEntries: Int)
}

/// Schedules and drives automatic re-delivery attempts for recipients whose
/// most recent delivery attempt came back `.queuedForRetry` (plan §4.8).
/// Holds no connections/pools of its own -- it calls back into whatever
/// `redeliver` closure its owner (`DirectMXTransport`) supplied at `init`,
/// exactly the same way `DirectMXTransport.send` itself would attempt
/// delivery, so a re-attempt goes through the identical MX-resolution +
/// host-fallback + circuit-breaker path as the original attempt (the
/// destination may have changed MX hosts, recovered from a breaker trip,
/// etc. between attempts).
///
/// **Reentrancy discipline** (matching the care `SMTPConnectionPool`'s
/// review required in Phase 1): every mutation of `entries`/`loopTask`/
/// `currentSleepTarget` happens synchronously, in one actor activation,
/// with no `await` in between the read and the write -- e.g.
/// `attemptRedelivery` removes an entry from `entries` *before* the `await
/// redeliver(...)` call that might reschedule it, so a concurrent
/// `shutdown()` racing against an in-flight redelivery attempt can never
/// see (and double-report) an entry that's actively being processed.
public actor DirectMXRetryQueue {
    // MARK: - Configuration

    public struct Configuration: Sendable {
        /// The 421-vs-greylist-vs-other-4yz backoff durations (plan §4.8).
        /// A `RetryBackoffPolicy` (`PerfectSMTPCore`), not three separate
        /// fields on this type, specifically so `SMTPConnection` (Phase 1's
        /// RCPT/DATA-phase rejection classification) and this actor (every
        /// MAIL-FROM-phase rejection and every rescheduled retry,
        /// regardless of phase) apply the exact same configured policy
        /// instead of two independently-hardcoded copies of it --
        /// `DirectMXTransport` passes this same `backoff` value to every
        /// `SMTPConnection` it dials (see `DirectMXTransport.makeDialer`),
        /// closing the gap Phase 1's own doc comment on `outcomeFor` left
        /// open ("Phase 1's job is correct single-attempt classification,
        /// not a full retry scheduler... make them properly configurable"
        /// -- this is that, applied consistently at every phase a
        /// rejection can occur, not just the one this actor happens to
        /// touch directly).
        public var backoff: RetryBackoffPolicy
        /// Maximum number of delivery attempts (the first attempt, made by
        /// `DirectMXTransport.send` itself before anything is ever
        /// enqueued here, counts as attempt 1) before a still-transiently-
        /// failing entry becomes `.expired` instead of being rescheduled
        /// again. Default 10 -- generous headroom given `maxAge` below is
        /// the primary ceiling in practice (a 15-minute 421 backoff alone
        /// would only reach ~2.5 hours after 10 attempts).
        public var maxAttempts: Int
        /// Maximum wall-clock age (measured from the *first* time a given
        /// recipient's delivery was queued for retry, not from the most
        /// recent attempt) before a still-transiently-failing entry
        /// becomes `.expired`. Default 5 days (432,000s), matching
        /// conventional MTA give-up behavior (e.g. Postfix's
        /// `maximal_queue_lifetime` defaults to 5 days) -- plan §4.8's
        /// "~4-5 days" guidance.
        public var maxAge: TimeInterval
        /// FIX #6 (LOW-MEDIUM security, milestone security review): a hard
        /// ceiling on how many entries this queue will hold pending at
        /// once, regardless of how many distinct, transiently-failing
        /// domains a caller sends to. Nothing else in this actor bounds
        /// `entries`' size -- a high-volume or misbehaving caller
        /// repeatedly sending to many distinct, transiently-failing
        /// domains has no ceiling otherwise, and each `Entry` carries a
        /// full `SignedMessage` (not a reference), so memory is
        /// proportional to (pending recipients) × (message size).
        /// Default 10,000 -- generous headroom for realistic retry-queue
        /// depth (bounded in practice by `maxAge`'s 5-day window and
        /// realistic transient-failure rates) while still being a hard,
        /// finite ceiling. When `enqueue` would exceed this, the outcome
        /// is reported `.failed(DirectMXRetryQueueError.queueAtCapacity)`
        /// (via `onTerminalOutcome`, exactly like any other terminal
        /// outcome) rather than silently dropped or grown past the cap --
        /// losing track of real mail silently would be worse than
        /// surfacing a clear capacity-exceeded failure.
        public var maxTotalEntries: Int

        public init(
            backoff: RetryBackoffPolicy = .init(),
            maxAttempts: Int = 10,
            maxAge: TimeInterval = 5 * 24 * 3600,
            maxTotalEntries: Int = 10_000
        ) {
            self.backoff = backoff
            self.maxAttempts = maxAttempts
            self.maxAge = maxAge
            self.maxTotalEntries = maxTotalEntries
        }

        /// Mechanically classifies a non-2yz/non-permanent `SMTPReply` into
        /// a `.queuedForRetry` outcome carrying the correct backoff for its
        /// class. `attempt` is the attempt number this classification
        /// applies *to* (the one about to be scheduled), supplied by the
        /// caller since this function has no notion of an entry's history.
        public func classify(_ reply: SMTPReply, attempt: Int) -> DeliveryResult.Outcome {
            backoff.classify(reply, attempt: attempt)
        }

        /// True when an entry that just reached `attempt` (about to be
        /// scheduled) or has been pending since `firstQueuedAt` has hit
        /// either ceiling and must become `.expired` instead of being
        /// rescheduled again.
        func isPastCeiling(attempt: Int, firstQueuedAt: Date) -> Bool {
            attempt > maxAttempts || Date().timeIntervalSince(firstQueuedAt) >= maxAge
        }
    }

    // MARK: - Entry

    /// One pending retry: enough state to redrive delivery for
    /// `recipients` without needing anything else from the caller.
    /// Matches `DeliveryResult.Outcome.queuedForRetry`'s existing shape
    /// (`nextAttempt`/`attempt`/`last`) rather than redefining an
    /// overlapping type, per this task's explicit instruction.
    public struct Entry: Sendable, Identifiable {
        public let id: UUID
        /// Always a single recipient in practice -- `DirectMXTransport`
        /// enqueues one `Entry` per recipient rather than batching
        /// recipients that failed together in the same transaction (e.g. a
        /// shared `MAIL FROM`-level rejection) into one entry. This is a
        /// deliberate simplification: batching would need `SMTPReply` to
        /// be `Hashable` (it currently is not) to key the grouping, and --
        /// more importantly -- two recipients that started out sharing one
        /// `last` reply can legitimately diverge on retry (one recipient's
        /// `RCPT TO` might now be accepted while another's is rejected),
        /// so per-recipient entries are simply the correct granularity
        /// once a second attempt is possible, not just the easiest one.
        /// The array shape is kept (rather than a single `String`) so nothing
        /// about this type's public shape has to change if a future caller
        /// wants to batch after all.
        public let recipients: [String]
        public let mailFrom: ReversePath
        public let message: SignedMessage
        public var nextAttempt: Date
        public var attempt: Int
        public var last: SMTPReply
        /// The wall-clock time this recipient's delivery was *first*
        /// queued for retry -- preserved across every reschedule (never
        /// reset to "now" on a subsequent attempt) so `maxAge` measures
        /// total time-since-first-failure, not time-since-most-recent-
        /// attempt.
        public let firstQueuedAt: Date
    }

    // MARK: - Storage / lifecycle

    private var entries: [UUID: Entry] = [:]
    private let configuration: Configuration
    private let redeliver: @Sendable (SMTPEnvelope, SignedMessage) async -> [DeliveryResult]
    private let onTerminalOutcome: (@Sendable (DeliveryResult) async -> Void)?
    private var loopTask: Task<Void, Never>?
    /// Bumped every time `nudgeLoop` starts a loop task; each task is
    /// handed the value current when it was started. Only the task
    /// holding the current generation is `loopTask`, so a task can tell
    /// whether it has been superseded.
    private var loopGeneration = 0
    /// The wall-clock instant the currently-running loop iteration is
    /// asleep until, if any -- read by `enqueue`/`reschedule` to decide
    /// whether a newly-arrived entry is due earlier than what the loop is
    /// already waiting for, and therefore worth nudging the loop awake for
    /// (plan's "sleeping until the next known nextAttempt... where
    /// practical" efficiency instruction).
    private var currentSleepTarget: Date?
    private var isShutDown = false
    /// FIX #3 regression-test instrumentation only (concurrency +
    /// SMTP-protocol reviews): incremented for every `processDueEntries()`
    /// call made by a loop task that is no longer the current one. A
    /// leaked zombie loop task (the bug this counter exists to make
    /// observable) is exactly that -- whether it kept going after
    /// `nudgeLoop` cancelled it, or was never cancelled at all -- so the
    /// expected value is always 0. This counts the bug's signature rather
    /// than the total number of passes, because the total depends on
    /// timing: `Task.sleep` runs on the monotonic clock while "due" is
    /// judged by `Date()`, so a wall clock step can wake the loop before
    /// anything is due and cost one harmless extra pass, and a starved
    /// scheduler can fold two due entries into one pass.
    /// Not `public` -- read via `@testable import` from
    /// `DirectMXRetryQueueTests`.
    private(set) var processDueEntriesFromSupersededLoopCountForTesting = 0

    /// - Parameters:
    ///   - redeliver: Attempts delivery exactly once more for the
    ///     envelope/message supplied, returning per-recipient results the
    ///     same way `DirectMXTransport.send` does. Never expected to
    ///     throw in practice (`DirectMXTransport`'s own delivery path
    ///     classifies every failure into a `DeliveryResult` rather than
    ///     throwing -- see that type's doc comments) but this closure's
    ///     signature is intentionally non-throwing so a caller providing a
    ///     custom `redeliver` can't accidentally leave a due entry
    ///     permanently stuck by throwing instead of returning a result.
    ///   - onTerminalOutcome: Invoked once for every recipient that
    ///     reaches a terminal state (`.delivered`, `.permanentlyFailed`,
    ///     `.expired`, `.ambiguous`, or `.failed`) while owned by this
    ///     queue -- the only way a caller observes the *final* outcome of
    ///     a background retry, since the original `send(_:_:)` call that
    ///     first produced `.queuedForRetry` already returned long before
    ///     this queue's own background loop gets around to redriving it.
    ///     `nil` (the default) means the caller isn't interested in
    ///     retry outcomes beyond `pendingEntriesSnapshot()`.
    public init(
        configuration: Configuration = .init(),
        redeliver: @escaping @Sendable (SMTPEnvelope, SignedMessage) async -> [DeliveryResult],
        onTerminalOutcome: (@Sendable (DeliveryResult) async -> Void)? = nil
    ) {
        self.configuration = configuration
        self.redeliver = redeliver
        self.onTerminalOutcome = onTerminalOutcome
    }

    // MARK: - Public API

    /// Enqueues `recipients` for automatic retry if -- and only if --
    /// `outcome` is `.queuedForRetry`. Every other case (`.delivered`,
    /// `.permanentlyFailed`, `.expired`, `.failed`, and critically
    /// `.ambiguous`) is a deliberate no-op: `.ambiguous` in particular must
    /// **never** be auto-retried (plan §4.8 -- a retry after an ambiguous
    /// failure risks double delivery), and this guard is the one place
    /// that invariant is enforced for this queue, structurally rather than
    /// by caller discipline.
    @discardableResult
    public func enqueue(
        recipients: [String], mailFrom: ReversePath, message: SignedMessage, outcome: DeliveryResult.Outcome
    ) async -> Bool {
        guard case .queuedForRetry(let nextAttempt, let attempt, let last) = outcome else { return false }
        guard !isShutDown else { return false }
        // FIX #6 (LOW-MEDIUM security, milestone security review): checked
        // before anything else is allocated for this entry -- see
        // `Configuration.maxTotalEntries`'s doc comment for why this cap
        // exists and why exceeding it is reported as a terminal `.failed`
        // outcome rather than silently dropped or left to grow the
        // dictionary without bound.
        guard entries.count < configuration.maxTotalEntries else {
            await reportTerminal(
                recipients: recipients,
                outcome: .failed(DirectMXRetryQueueError.queueAtCapacity(maxTotalEntries: configuration.maxTotalEntries))
            )
            return false
        }
        let firstQueuedAt = Date()
        if configuration.isPastCeiling(attempt: attempt, firstQueuedAt: firstQueuedAt) {
            // Defensive: only reachable if a caller enqueues an
            // already-past-ceiling outcome directly (e.g. `maxAttempts ==
            // 0`) -- `DirectMXTransport`'s own first enqueue always starts
            // at `attempt == 1`, which cannot itself be past a sane
            // ceiling.
            await reportTerminal(recipients: recipients, outcome: .expired(attempts: attempt, last: last))
            return false
        }
        let entry = Entry(
            id: UUID(), recipients: recipients, mailFrom: mailFrom, message: message,
            nextAttempt: nextAttempt, attempt: attempt, last: last, firstQueuedAt: firstQueuedAt
        )
        entries[entry.id] = entry
        nudgeLoop(forCandidate: nextAttempt)
        return true
    }

    /// A point-in-time snapshot of every entry still pending (not yet
    /// resolved to a terminal outcome). Exists both for tests and for a
    /// caller who wants programmatic visibility into what's still
    /// in-flight without wiring up `onTerminalOutcome` -- see
    /// `shutdown()`'s doc comment for why this matters specifically at
    /// shutdown time.
    public func pendingEntriesSnapshot() -> [Entry] {
        Array(entries.values)
    }

    /// Cancels the background loop and reports every still-pending
    /// recipient as a terminal `.failed(DirectMXRetryQueueError
    /// .shutdownWhilePending)` outcome (via `onTerminalOutcome`, if one was
    /// supplied) before returning.
    ///
    /// **Design decision, worked through explicitly per this task's
    /// instructions:** unlike `SMTPConnectionPool.shutdown()`, there is no
    /// waiter/continuation queue to drain here. Nothing ever calls into
    /// this actor and suspends waiting for a *result* -- `enqueue` returns
    /// immediately once an entry is recorded, and retries are driven
    /// entirely by this actor's own internal timer loop, invisible to any
    /// external caller's control flow. So there is no continuation that
    /// would otherwise hang forever the way a pool waiter would.
    ///
    /// What *would* be lost by a shutdown that merely cancelled the loop
    /// and returned is information: every recipient still sitting in
    /// `entries` at that moment has, from the caller's point of view,
    /// simply vanished -- no `.delivered`, no `.permanentlyFailed`, no
    /// `.expired`, nothing. For a library whose retry queue is explicitly
    /// in-memory-only (see this file's header comment), silently
    /// discarding that information on shutdown would be the one place a
    /// caller could lose track of real, possibly-still-deliverable mail
    /// without ever being told. So `shutdown()` drains `entries` and
    /// reports each one via `onTerminalOutcome` (if wired up) carrying its
    /// last-known attempt count and reply, and `pendingEntriesSnapshot()`
    /// gives the same information programmatically to a caller who calls
    /// it just before `shutdown()` instead.
    public func shutdown() async {
        isShutDown = true
        loopTask?.cancel()
        loopTask = nil
        currentSleepTarget = nil
        let draining = entries
        entries.removeAll()
        for entry in draining.values {
            await reportTerminal(
                recipients: entry.recipients,
                outcome: .failed(DirectMXRetryQueueError.shutdownWhilePending(attempt: entry.attempt, last: entry.last))
            )
        }
    }

    // MARK: - Background loop

    /// Starts the loop if it isn't already running, or -- if it's
    /// currently asleep waiting for a `nextAttempt` later than `candidate`
    /// -- cancels and restarts it so it wakes promptly for the newly
    ///-arrived earlier entry instead of oversleeping until its stale
    /// target. `Task.sleep`'s `CancellationError` from this restart is
    /// indistinguishable, at the point it's thrown, from a `shutdown()`-
    /// triggered cancellation; `runLoop` doesn't need to tell them apart --
    /// FIX #3 made it check `Task.isCancelled` in addition to `isShutDown`
    /// immediately after the sleep, so *either* cause makes that exact
    /// task instance exit rather than only `shutdown()` doing so (which
    /// previously let a nudge-cancelled task fall through and keep running
    /// as a permanent duplicate of the replacement task started below).
    private func nudgeLoop(forCandidate candidate: Date) {
        guard !isShutDown else { return }
        guard loopTask != nil else {
            startLoop()
            return
        }
        if let currentSleepTarget, candidate < currentSleepTarget {
            loopTask?.cancel()
            startLoop()
        }
    }

    private func startLoop() {
        loopGeneration += 1
        let generation = loopGeneration
        loopTask = Task { [weak self] in await self?.runLoop(generation: generation) }
    }

    /// `[weak self]` at every `Task` creation site in this file (here and
    /// in `nudgeLoop`) deliberately: this loop is the *only* thing that
    /// would otherwise keep this actor alive indefinitely once every
    /// external strong reference to it is dropped (there is no other
    /// self-referencing cycle in this type). A strong `self` capture here
    /// would mean a `DirectMXRetryQueue` a caller stopped using -- without
    /// ever calling `shutdown()` -- leaks for the lifetime of the process
    /// even after becoming unreachable. With `weak self`, once the last
    /// external reference drops, the actor can deinitialize; this loop's
    /// next wake finds `self == nil` and exits.
    private func runLoop(generation: Int) async {
        // `!Task.isCancelled` here too: a replacement that `nudgeLoop`
        // cancels before it ever runs must not publish a
        // `currentSleepTarget` of its own on the way out. If it did while
        // the live loop was mid-pass, a later nudge could cancel the live
        // loop in the middle of `redeliver`. (Not covered by a test; the
        // interleaving is too narrow to provoke reliably.)
        while !isShutDown, !Task.isCancelled {
            guard let sleepUntil = entries.values.map(\.nextAttempt).min() else {
                // Nothing pending -- exit; `nudgeLoop` restarts this loop
                // the next time `enqueue` adds something, so no wakeup is
                // wasted polling an empty queue (the efficiency point
                // called out in this task's brief). `loopTask` must be
                // cleared for that restart to happen: `nudgeLoop` only
                // starts a loop when `loopTask` is nil, and with no sleep
                // target it never nudges either, so leaving it set meant
                // nothing enqueued after the queue first drained was ever
                // retried. A loop that got here is the current one (the
                // `while` condition rules out a cancelled, superseded
                // task); the generation check just makes that explicit.
                if generation == loopGeneration { loopTask = nil }
                return
            }
            currentSleepTarget = sleepUntil
            let interval = max(0, sleepUntil.timeIntervalSinceNow)
            do {
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            } catch {
                // Cancelled -- either `shutdown()` or a `nudgeLoop` restart
                // for an earlier-arriving entry. Nothing to do in the
                // `catch` block itself; the check below (not just
                // `isShutDown`) is what actually disambiguates and exits
                // promptly on either.
            }
            // FIX #3 (concurrency + SMTP-protocol reviews, independently
            // converged on the same bug): a *nudge*-triggered cancellation
            // (`nudgeLoop` cancelling this exact task instance to start a
            // fresh replacement for an earlier-arriving entry) must make
            // *this* task instance exit immediately -- previously only
            // `isShutDown` was checked here, so a nudge-cancelled task's
            // `Task.sleep` threw, was silently swallowed by the `catch`
            // above, and this loop fell straight through into
            // `processDueEntries()` and back around `while !isShutDown`,
            // continuing to run as an independent, permanently-live
            // duplicate of the replacement task `nudgeLoop` had already
            // started. Every subsequent nudge that raced ahead of an
            // in-flight sleep (routine under real traffic -- different
            // domains' backoffs land at different times) spawned another
            // such zombie, an unbounded task leak, and made `shutdown()`'s
            // single `loopTask?.cancel()` insufficient (it only ever
            // reached the *current* reference, never any earlier zombies).
            // `Task.isCancelled` is the correct signal here (not folded
            // into the `catch` above) because it must also cover the rare
            // case where `Task.sleep` happens to return normally in the
            // same instant cancellation is requested -- cancellation of
            // this specific task instance always means "stop, a
            // replacement may already be running or the queue is
            // shutting down," never "keep going regardless of how the
            // sleep returned."
            guard !isShutDown, !Task.isCancelled else { return }
            // Cleared only after the check above. A cancelled task may
            // resume after `nudgeLoop`'s replacement has already set its
            // own target; clearing it from here wiped that target, so the
            // next earlier-due `enqueue` skipped its nudge and the entry
            // waited for the replacement's later wake. (`shutdown()`
            // clears it itself.)
            currentSleepTarget = nil
            await processDueEntries(generation: generation)
        }
    }

    private func processDueEntries(generation: Int) async {
        if generation != loopGeneration { processDueEntriesFromSupersededLoopCountForTesting += 1 }
        let now = Date()
        let due = entries.values.filter { $0.nextAttempt <= now }
        for entry in due {
            // Re-check presence: `attemptRedelivery` below removes entries
            // synchronously before its own `await`, but this loop itself
            // has no `await` between entries, so this is defensive, not
            // load-bearing -- kept for clarity that "due" is a snapshot
            // that could in principle go stale.
            guard entries[entry.id] != nil else { continue }
            await attemptRedelivery(entry)
        }
    }

    /// Redrives delivery for one due entry. Removes the entry from
    /// `entries` *before* the `await redeliver(...)` call below --
    /// reentrancy discipline (this file's header comment): a concurrent
    /// `shutdown()` or another `processDueEntries` pass (not possible
    /// today since the loop is the sole driver of this method, but kept as
    /// a structural guarantee rather than an incidental one) can never
    /// observe this entry mid-flight and double-process it.
    private func attemptRedelivery(_ entry: Entry) async {
        entries.removeValue(forKey: entry.id)
        let envelope: SMTPEnvelope
        do {
            envelope = try SMTPEnvelope(mailFrom: entry.mailFrom, recipients: entry.recipients)
        } catch {
            // `entry.recipients` were already validated once, when the
            // envelope that originally produced this entry was
            // constructed -- this should be unreachable, but if it somehow
            // isn't, surface it as terminal rather than looping forever on
            // a request that can never construct a valid envelope.
            await reportTerminal(recipients: entry.recipients, outcome: .failed(error))
            return
        }
        let results = await redeliver(envelope, entry.message)
        await handle(results: results, entry: entry)
    }

    /// **Important subtlety this method exists to handle correctly:** the
    /// `attempt` value embedded in a freshly-returned `.queuedForRetry`
    /// outcome is *not* trustworthy as a retry-history counter. Every
    /// classification site that produces one -- `SMTPConnection.outcomeFor`
    /// (RCPT/DATA-phase rejections) and `DirectMXTransport.classify
    /// (smtpError:)` (MAIL-FROM-phase rejections) alike -- has no memory of
    /// prior attempts at all: each is a single, fresh SMTP transaction that
    /// always reports `attempt: 1`, because *it* has no idea this is
    /// actually retry number 4. If this method trusted that field, the
    /// retry ceiling's `maxAttempts` check could never fire (every
    /// redelivery would look like "attempt 1" forever, no matter how many
    /// times it had actually been tried) -- only `maxAge` would ever
    /// terminate a stuck entry, silently defeating half of plan §4.8's
    /// retry-ceiling requirement. So: the returned `attempt` is used only
    /// for the very first `enqueue(...)` call (a caller-supplied starting
    /// point -- see that method's doc comment for why a caller might
    /// legitimately seed a non-1 value, e.g. resuming their own persisted
    /// state). Every reschedule after that increments *this actor's own*
    /// `entry.attempt` by exactly one, regardless of what `redeliver`'s
    /// result reported -- this is the actual, trustworthy retry-history
    /// counter.
    private func handle(results: [DeliveryResult], entry: Entry) async {
        for result in results {
            switch result.outcome {
            case .delivered, .permanentlyFailed, .ambiguous, .failed, .expired:
                // `.expired` should never actually come back from
                // `redeliver` (that's this queue's own concept, not
                // something `DirectMXTransport.send` produces) -- handled
                // gracefully rather than assumed impossible.
                await reportTerminal(result)
            case .queuedForRetry(let nextAttempt, _, let last):
                let nextAttemptNumber = entry.attempt + 1
                if configuration.isPastCeiling(attempt: nextAttemptNumber, firstQueuedAt: entry.firstQueuedAt) {
                    await reportTerminal(DeliveryResult(recipient: result.recipient, outcome: .expired(attempts: nextAttemptNumber, last: last)))
                } else {
                    let rescheduled = Entry(
                        id: UUID(), recipients: [result.recipient], mailFrom: entry.mailFrom, message: entry.message,
                        nextAttempt: nextAttempt, attempt: nextAttemptNumber, last: last, firstQueuedAt: entry.firstQueuedAt
                    )
                    entries[rescheduled.id] = rescheduled
                    nudgeLoop(forCandidate: nextAttempt)
                }
            }
        }
    }

    private func reportTerminal(recipients: [String], outcome: DeliveryResult.Outcome) async {
        for recipient in recipients {
            await reportTerminal(DeliveryResult(recipient: recipient, outcome: outcome))
        }
    }

    private func reportTerminal(_ result: DeliveryResult) async {
        if let onTerminalOutcome { await onTerminalOutcome(result) }
    }
}

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
    /// The wall-clock instant the currently-running loop iteration is
    /// asleep until, if any -- read by `enqueue`/`reschedule` to decide
    /// whether a newly-arrived entry is due earlier than what the loop is
    /// already waiting for, and therefore worth nudging the loop awake for
    /// (plan's "sleeping until the next known nextAttempt... where
    /// practical" efficiency instruction).
    private var currentSleepTarget: Date?
    private var isShutDown = false
    /// Incremented each time a loop task is started; a loop only acts
    /// while its generation is current. See `startLoop()`.
    private var loopGeneration: UInt64 = 0

    /// FIX #3 regression-test instrumentation only (concurrency +
    /// SMTP-protocol reviews). Not `public` -- read via `@testable import`
    /// from `DirectMXRetryQueueTests`.
    ///
    /// The leaked zombie loop task that FIX #3 removed was a superseded
    /// loop task that kept running after `nudgeLoop` replaced it. These
    /// count it directly: `processDueEntries()` calls from a superseded
    /// (or cancelled) loop, which the fixed loop never makes, and loop
    /// tasks currently running, which settles at 1 or 0. (An earlier
    /// version of the regression test counted every `processDueEntries()`
    /// call and expected exactly 2. That depends on timing: a late wake-up
    /// can handle both entries in one pass, and since `nextAttempt` is
    /// wall-clock `Date` while `Task.sleep` is monotonic, a wake-up just
    /// before `Date()` reaches the target can add an empty pass. Both are
    /// harmless, but the test failed intermittently under load.)
    private(set) var processDueEntriesFromSupersededLoopCountForTesting = 0
    private(set) var liveLoopCountForTesting = 0
    /// How many times `nudgeLoop` took its cancel-and-restart branch, so
    /// the regression test can confirm it exercised that branch.
    private(set) var loopRestartCountForTesting = 0
    /// Whether the loop is currently asleep waiting for an entry, so a
    /// test can wait for that state instead of guessing with a sleep.
    var isLoopSleepingForTesting: Bool { currentSleepTarget != nil }

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
        loopGeneration &+= 1
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
            loopRestartCountForTesting += 1
            loopTask?.cancel()
            startLoop()
        }
    }

    /// Starts a new loop task as the current generation. Only the current
    /// generation's loop may touch `loopTask`, `currentSleepTarget` or
    /// process entries; a superseded one exits as soon as it wakes.
    private func startLoop() {
        loopGeneration &+= 1
        let generation = loopGeneration
        loopTask = Task { [weak self] in await self?.runLoop(generation: generation) }
    }

    /// Lifetime: `startLoop()` captures `self` weakly, but
    /// `await self?.runLoop(...)` holds it strongly for the whole call,
    /// sleeps included. So a queue a caller stopped using without calling
    /// `shutdown()` stays alive while it still has entries -- it keeps
    /// retrying them -- and is released once the loop runs out of work and
    /// returns. The weak capture only avoids retaining the queue from a
    /// task that hasn't started running yet.
    private func runLoop(generation: UInt64) async {
        liveLoopCountForTesting += 1
        defer { liveLoopCountForTesting -= 1 }
        while !isShutDown, generation == loopGeneration {
            guard let sleepUntil = entries.values.map(\.nextAttempt).min() else {
                // Nothing pending -- exit; `nudgeLoop` restarts this loop
                // the next time `enqueue` adds something, so no wakeup is
                // wasted polling an empty queue (the efficiency point
                // called out in this task's brief). Clearing `loopTask` is
                // what lets it: `nudgeLoop` only starts a loop when
                // `loopTask` is nil. (It used to stay set to this finished
                // task, so once the queue had drained, every later entry
                // sat in `entries` unprocessed until `shutdown()`.)
                loopTask = nil
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
            // A superseded loop (a newer generation exists) or a cancelled
            // one must leave before touching shared state: the
            // replacement may already be asleep, and clearing
            // `currentSleepTarget` here used to make the actor think no
            // loop was sleeping, so a later earlier-due entry didn't wake
            // it.
            guard generation == loopGeneration, !isShutDown, !Task.isCancelled else { return }
            currentSleepTarget = nil
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
            await processDueEntries(generation: generation)
        }
    }

    private func processDueEntries(generation: UInt64) async {
        if generation != loopGeneration || Task.isCancelled { processDueEntriesFromSupersededLoopCountForTesting += 1 }
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
                if isShutDown {
                    // `shutdown()` ran while this redelivery was in flight,
                    // so it couldn't report this entry. Report it now, as
                    // it would have been, instead of rescheduling into a
                    // queue whose loop will never run again.
                    await reportTerminal(DeliveryResult(
                        recipient: result.recipient,
                        outcome: .failed(DirectMXRetryQueueError.shutdownWhilePending(attempt: nextAttemptNumber, last: last))
                    ))
                } else if configuration.isPastCeiling(attempt: nextAttemptNumber, firstQueuedAt: entry.firstQueuedAt) {
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

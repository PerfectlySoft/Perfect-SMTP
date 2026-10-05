//
//  SMTPConnectionPool.swift
//  PerfectSMTP
//
//  Connection pool (plan §4.4). Per-destination keying by
//  `(host, port, tls)`. Bounded concurrency enforced under one lock (see
//  "Why a lock, not an actor" on `SMTPConnectionPool`).
//

import Foundation
import NIOConcurrencyHelpers
import NIOCore

/// Milestone review finding (documentation-only, no `Key` redesign this
/// pass): `Key` is `(host, port, tls)` **only** -- it has no credential or
/// tenant dimension. A connection dialed and authenticated for one
/// credential set is, from this pool's point of view, fungible with any
/// other checkout for the same `(host, port, tls)`, and will be handed back
/// out (already authenticated -- see `SMTPConnection.isAuthenticated`) to
/// whichever caller checks out next. This is safe **only** because
/// `RelayTransport` owns exactly one fixed `config.auth` per pool instance
/// -- every checkout against a given `RelayTransport`'s pool is implicitly
/// "the same identity" by construction, so there is no cross-credential
/// leakage in this package's own usage. **Integrators building multi-tenant
/// systems directly on top of the public `SMTPConnectionPool` API must not
/// share one pool instance across multiple credential sets against the same
/// `(host, port, tls)`** -- doing so risks a connection authenticated as
/// one identity being reused for another. If a future need justifies it,
/// `Key` could be extended with a credential fingerprint, but that redesign
/// is out of scope for this fix pass.
///
/// **Why a lock, not an actor.** This used to be an actor that parked
/// waiters from inside `withTaskCancellationHandler {
/// withCheckedThrowingContinuation { ... } }`, relying on those closures
/// inheriting its isolation. The same construct in `SMTPMailer`'s
/// `ResultChannel` ran off its actor's executor in Swift 6.4 optimized
/// builds (see that type's doc comment). Stress tests never caught this
/// pool doing it, but every pool decision (reuse, reserve, park, hand off,
/// cancel, shut down) now happens under one `NIOLockedValueBox`, so
/// correctness doesn't depend on executor inference. Cancellation removes
/// a parked waiter under the lock and resumes it directly, with no
/// unstructured `Task`. The lock is never held across an `await` or while
/// resuming a continuation, dialing, or closing a channel.
///
/// Freed capacity always reaches a waiter that can use it: a healthy
/// release hands its live connection to the oldest waiter for the same key;
/// any other freed slot -- an unhealthy release, a failed dial, or a slot
/// freed under the shared `maxTotal` -- is reserved for the oldest parked
/// waiter (across all keys) that `maxPerHost`/`maxTotal` allow, which dials
/// for itself. `maxTotal` counts idle and still-closing connections as well
/// as checked-out ones, so making room may close the oldest idle connection
/// of another key; a slot under `maxTotal` is freed only when a close has
/// completed, from the close's own callback. Waiters whose key's circuit
/// breaker is open fail with `SMTPError.circuitOpen` instead, exactly as a
/// fresh checkout would.
/// (The actor version only handed a slot to same-key waiters, and only on
/// release, so a waiter could stay parked forever after a failed dial or
/// behind another host's `maxTotal` usage.)
public final class SMTPConnectionPool: Sendable {
    public struct Key: Hashable, Sendable {
        public let host: String
        public let port: Int
        public let tls: TLSMode
        public init(host: String, port: Int, tls: TLSMode) {
            self.host = host
            self.port = port
            self.tls = tls
        }
    }

    public struct Configuration: Sendable {
        /// The most connections to one `Key` at once, checked out (or being
        /// dialed) or idle. A connection the pool has started closing
        /// doesn't count here (it counts toward `maxTotal` until the close
        /// completes), so a replacement can be dialed right away; the
        /// server may briefly see one extra connection while the old one
        /// finishes closing.
        public var maxPerHost: Int
        /// The most open connections across all keys at once: checked out
        /// (or being dialed), idle, or still closing. When a new connection
        /// is needed at this limit, the pool closes the oldest idle
        /// connection (for any key), and the checkout waits until that
        /// close completes; if none is idle, it waits for a connection to
        /// be released. A close is usually immediate, but a TLS close waits
        /// for the peer's close_notify, up to NIOSSL's shutdown timeout
        /// (5 s by default) for an unresponsive peer -- so at this limit, a
        /// checkout can wait that long for a slot.
        public var maxTotal: Int
        public var idleTimeout: TimeInterval
        public var connectTimeout: TimeAmount
        public var circuitBreakerThreshold: Int
        public var circuitBreakerResetTimeout: TimeInterval
        /// FIX #4 (plan §7, milestone architecture review): per-command
        /// reply/write timeout threaded into every pool-dialed
        /// `SMTPConnection`, so a hung/black-holed remote server can't pin
        /// a pooled connection indefinitely (see `SMTPConnection`'s own
        /// doc comments). RFC 5321 §4.5.3.2's general per-command minimum.
        public var replyTimeout: TimeInterval
        /// FIX #4's phase-specific exception: RFC 5321 §4.5.3.2's longer
        /// minimum specifically for the final reply after the DATA
        /// terminator, where the server may legitimately be doing real
        /// work (spooling/scanning a large message).
        public var dataTerminationTimeout: TimeInterval

        public init(
            maxPerHost: Int = 4,
            maxTotal: Int = 32,
            idleTimeout: TimeInterval = 60,
            connectTimeout: TimeAmount = .seconds(30),
            circuitBreakerThreshold: Int = 5,
            circuitBreakerResetTimeout: TimeInterval = 30,
            replyTimeout: TimeInterval = 300,
            dataTerminationTimeout: TimeInterval = 600
        ) {
            self.maxPerHost = maxPerHost
            self.maxTotal = maxTotal
            self.idleTimeout = idleTimeout
            self.connectTimeout = connectTimeout
            self.circuitBreakerThreshold = circuitBreakerThreshold
            self.circuitBreakerResetTimeout = circuitBreakerResetTimeout
            self.replyTimeout = replyTimeout
            self.dataTerminationTimeout = dataTerminationTimeout
        }
    }

    public enum PoolError: Error, Sendable, Equatable {
        case shutdown
    }

    /// What a checkout ends up with once its decision is made under the
    /// lock -- immediately, or later when a parked waiter is resolved.
    /// Slot ownership transfers under the same lock acquisition that
    /// dequeues the waiter (plan §4.4), so a fresh checkout can't race in
    /// and steal it.
    private enum CheckoutOutcome: Sendable {
        /// A live connection: reused from idle, or handed over directly by
        /// a healthy release. `activeCount` already includes it.
        case connection(SMTPConnection)
        /// A slot (not a connection) is reserved for this checkout, which
        /// must dial for itself outside the lock. `activeCount` already
        /// includes it.
        case dialYourself
    }

    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<CheckoutOutcome, any Error>
    }

    private struct IdleEntry {
        let connection: SMTPConnection
        let returnedAt: DispatchTime
    }

    private enum BreakerState {
        case closed(consecutiveFailures: Int)
        case open(until: DispatchTime)
    }

    /// Continuations to resume and channels to close once the lock is
    /// released (see `lockedEffects` and `run`).
    private struct Effects {
        var resumes: [(CheckedContinuation<CheckoutOutcome, any Error>, Result<CheckoutOutcome, any Error>)] = []
        var closes: [(connection: SMTPConnection, isEviction: Bool)] = []
    }

    private struct State {
        var idle: [Key: [IdleEntry]] = [:]
        var activeCount: [Key: Int] = [:]
        var breaker: [Key: BreakerState] = [:]
        var waiters: [Key: [Waiter]] = [:]
        var isShutDown = false
        var nextWaiterID: UInt64 = 0

        var totalActive: Int { activeCount.values.reduce(0, +) }
        var totalIdle: Int { idle.values.reduce(0) { $0 + $1.count } }
        /// Connections the pool has started closing whose close hasn't
        /// completed yet.
        var closing = 0
        /// How many of `closing` are evictions -- idle connections closed
        /// specifically to make room under `maxTotal` for a waiting
        /// checkout. Other closes (an unhealthy release, a stale idle
        /// connection) may be slow, so they don't count as room on its way.
        var evicting = 0
        /// Closes decided under the current lock acquisition, not yet
        /// issued; `lockedEffects` hands them to `run(_:)`.
        var queuedCloses: [(connection: SMTPConnection, isEviction: Bool)] = []

        /// The only way the pool closes a connection: it keeps counting
        /// toward `maxTotal` from this moment until `closeFinished()`.
        mutating func beginClosing(_ connection: SMTPConnection, isEviction: Bool = false) {
            closing += 1
            if isEviction { evicting += 1 }
            queuedCloses.append((connection, isEviction))
        }
        /// Every open connection the pool is responsible for: checked out,
        /// being dialed (a reserved slot), idle, or still closing.
        var totalOpen: Int { totalActive + totalIdle + closing }

        /// Gives up one reserved or checked-out slot for `key`. Drops the
        /// entry at zero, so the totals above stay proportional to the keys
        /// in use rather than every key the pool has ever seen.
        mutating func releaseSlot(_ key: Key) {
            let remaining = activeCount[key, default: 1] - 1
            activeCount[key] = remaining > 0 ? remaining : nil
        }
    }

    private let state = NIOLockedValueBox(State())
    private let configuration: Configuration
    private let group: any EventLoopGroup
    private let ehloHostname: String
    /// Injectable for testing (e.g. racing checkouts against a pool with
    /// `maxPerHost = 1` without a real socket). Defaults to the real
    /// `SMTPBootstrap`-backed dialer.
    private let dialer: @Sendable (Key) async throws -> SMTPConnection

    /// `DispatchTime` (not `ContinuousClock`, for macOS 13.0-independence
    /// -- see `Documentation/macos-deployment-targets.md`'s 13.0 baseline)
    /// -- same wall-clock-adjustment immunity `ContinuousClock` provided,
    /// just via an older, more verbose API.
    private static func dispatchDeadline(secondsFromNow: TimeInterval) -> DispatchTime {
        DispatchTime(uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds &+ UInt64(max(0, secondsFromNow) * 1_000_000_000))
    }

    public init(configuration: Configuration = .init(), ehloHostname: String = "localhost", group: any EventLoopGroup) {
        self.configuration = configuration
        self.ehloHostname = ehloHostname
        self.group = group
        let capturedGroup = group
        let capturedTimeout = configuration.connectTimeout
        let capturedHostname = ehloHostname
        let capturedReplyTimeout = configuration.replyTimeout
        let capturedDataTerminationTimeout = configuration.dataTerminationTimeout
        self.dialer = { key in
            let asyncChannel = try await SMTPBootstrap.connect(
                host: key.host, port: key.port, tls: key.tls,
                connectTimeout: capturedTimeout, group: capturedGroup
            )
            let connection = SMTPConnection(
                asyncChannel: asyncChannel,
                ehloHostname: capturedHostname,
                replyTimeout: capturedReplyTimeout,
                dataTerminationTimeout: capturedDataTerminationTimeout
            )
            do {
                try await connection.negotiateCapabilities()
            } catch {
                // Close and wait before throwing: the pool frees this
                // dial's slot as soon as the dialer throws.
                await connection.closeAndWait()
                throw error
            }
            return connection
        }
    }

    /// Test/internal-only initializer: overrides the dialer entirely so
    /// pool behavior (reentrancy, cancellation, breaker) can be exercised
    /// without a real socket. A dialer that fails after opening a socket
    /// must close it, and wait for the close, before throwing: the pool
    /// frees the dial's slot as soon as the dialer throws. (The default
    /// dialer does; for TLS that wait can take up to NIOSSL's close_notify
    /// timeout, 5 s by default, against an unresponsive peer.)
    init(configuration: Configuration = .init(), group: any EventLoopGroup, dialer: @escaping @Sendable (Key) async throws -> SMTPConnection) {
        self.configuration = configuration
        self.ehloHostname = "localhost"
        self.group = group
        self.dialer = dialer
    }

    // MARK: - Public API

    /// - Parameters:
    ///   - isHealthy: Milestone review finding (architecture + SMTP-
    ///     protocol reviews, independently converged on the same root
    ///     cause): a mail transaction can complete and `body` can return
    ///     *normally* -- no thrown error at all -- even though the
    ///     connection it ran over is no longer safe to reuse. Both
    ///     `RelayTransport.sendMessage`'s and `DirectMXTransport
    ///     .attemptOnHost`'s message-level rejection handling deliberately
    ///     *return* (never throw) an outcome like `.ambiguous` (a
    ///     mid-DATA disconnect -- plan §4.8's point of no return: the peer
    ///     may or may not have accepted the message, and the socket may
    ///     already be half-closed) or a `421` reply (RFC 5321 §4.2.1: the
    ///     peer's own explicit "service unavailable, closing the
    ///     transmission channel"), precisely so a message-level rejection
    ///     doesn't get mistaken for a connection-level failure by the
    ///     caller's own host-fallback logic. But that same "return, don't
    ///     throw" design meant this method previously had no way to learn
    ///     that the connection died (or was told to die) anyway -- every
    ///     normal return of `body` was unconditionally treated as
    ///     `healthy: true`, so a connection that just disconnected
    ///     mid-DATA or received a `421` never fed the circuit breaker's
    ///     failure count and was never proactively closed (left to a race
    ///     on `channel.isActive` instead -- see `release`). `isHealthy`
    ///     closes that gap: it inspects `body`'s actual return value and
    ///     decides. Defaults to `{ _ in true }` so any caller that doesn't
    ///     supply one keeps this method's original behavior exactly
    ///     (`R == Void`, the pool's own tests, etc.) -- callers whose `R`
    ///     is `[DeliveryResult]` should pass
    ///     `SMTPConnectionPool.deliveryResultsIndicateHealthyConnection`.
    public func withConnection<R: Sendable>(
        to key: Key,
        isHealthy: (R) -> Bool = { _ in true },
        _ body: (SMTPConnection) async throws -> R
    ) async throws -> R {
        let connection = try await checkout(key)
        do {
            let result = try await body(connection)
            release(key, connection: connection, healthy: isHealthy(result))
            return result
        } catch {
            release(key, connection: connection, healthy: false)
            throw error
        }
    }

    /// Closes every idle connection, fails every parked checkout with
    /// `PoolError.shutdown`, and makes later checkouts fail the same way.
    /// Connections checked out at the time are closed when released.
    /// (`async` for source compatibility with the actor version.)
    public func shutdown() async {
        let effects = lockedEffects { state, effects in
            state.isShutDown = true
            for (_, entries) in state.idle {
                for entry in entries { state.beginClosing(entry.connection) }
            }
            state.idle.removeAll()
            for (_, list) in state.waiters {
                for waiter in list { effects.resumes.append((waiter.continuation, .failure(PoolError.shutdown))) }
            }
            state.waiters.removeAll()
            return
        }
        run(effects)
    }

    // MARK: - Effects

    /// Runs `body` under the lock and returns what it decided to do once
    /// the lock is released. Every connection `body` closes keeps counting
    /// toward `maxTotal` (`State.closing`) until its close has actually
    /// completed, so open sockets never exceed `maxTotal`, even briefly;
    /// see `run(_:)`.
    private func lockedEffects(_ body: (inout State, inout Effects) -> Void) -> Effects {
        state.withLockedValue { state in
            var effects = Effects()
            body(&state, &effects)
            effects.closes = state.queuedCloses
            state.queuedCloses.removeAll()
            return effects
        }
    }

    /// Closes and resumes what a `lockedEffects` block decided, outside the
    /// lock. When each close completes, its slot is freed and parked
    /// waiters are admitted.
    private func run(_ effects: Effects) {
        for (connection, isEviction) in effects.closes {
            connection.channel.close(promise: nil)
            connection.channel.closeFuture.whenComplete { _ in self.closeFinished(wasEviction: isEviction) }
        }
        for (continuation, result) in effects.resumes { continuation.resume(with: result) }
    }

    private func closeFinished(wasEviction: Bool) {
        let effects = lockedEffects { state, effects in
            state.closing -= 1
            if wasEviction { state.evicting -= 1 }
            admitWaiters(state: &state, effects: &effects)
        }
        run(effects)
    }

    // MARK: - Checkout

    private func checkout(_ key: Key) async throws -> SMTPConnection {
        let id = state.withLockedValue { state in
            state.nextWaiterID &+= 1
            return state.nextWaiterID
        }
        let outcome: CheckoutOutcome = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<CheckoutOutcome, any Error>) in
                let effects = lockedEffects { state, effects in
                    let decision = decideCheckout(key, state: &state)
                    switch decision {
                    case .some(let result):
                        effects.resumes.append((continuation, result))
                    case .none:
                        // Checked under the lock: the cancellation flag is
                        // set before `onCancel` runs, so either this sees
                        // it, or `onCancel` (same lock) finds the waiter.
                        if Task.isCancelled {
                            effects.resumes.append((continuation, .failure(CancellationError())))
                        } else {
                            state.waiters[key, default: []].append(Waiter(id: id, continuation: continuation))
                        }
                    }
                    return
                }
                run(effects)
            }
        } onCancel: {
            let waiter: Waiter? = state.withLockedValue { state in
                guard var list = state.waiters[key], let index = list.firstIndex(where: { $0.id == id }) else { return nil }
                let waiter = list.remove(at: index)
                state.waiters[key] = list.isEmpty ? nil : list
                return waiter
            }
            waiter?.continuation.resume(throwing: CancellationError())
        }

        switch outcome {
        case .connection(let connection):
            return connection
        case .dialYourself:
            do {
                let connection = try await dialer(key)
                state.withLockedValue { recordSuccess(key, state: &$0) }
                return connection
            } catch {
                // The reservation is given up: pass it to a waiter that can
                // use it, or free it.
                let effects = lockedEffects { state, effects in
                    recordFailure(key, state: &state)
                    state.releaseSlot(key)
                    admitWaiters(state: &state, effects: &effects)
                    return
                }
                run(effects)
                throw error
            }
        }
    }

    /// The immediate checkout decision, made under the lock: a result, or
    /// `nil` meaning "park". Reserving a slot here, before any `await`, is
    /// what keeps concurrent checkouts from overshooting `maxPerHost`
    /// (plan §4.4's reentrancy discipline).
    private func decideCheckout(
        _ key: Key, state: inout State
    ) -> Result<CheckoutOutcome, any Error>? {
        if state.isShutDown { return .failure(PoolError.shutdown) }
        if isBreakerOpen(key, state: &state) { return .failure(SMTPError.circuitOpen) }
        if let reused = popValidatedIdle(key, state: &state) {
            state.activeCount[key, default: 0] += 1
            return .success(.connection(reused))
        }
        if makeRoomForNewConnection(to: key, isNewCheckout: true, state: &state) {
            state.activeCount[key, default: 0] += 1
            return .success(.dialYourself)
        }
        return nil
    }

    /// Whether a new connection to `key` may be opened now. `maxTotal`
    /// counts idle and still-closing connections too. At the limit, this
    /// starts closing the oldest idle connections (of any key), one per
    /// checkout that `maxTotal` alone is holding back -- the parked
    /// waiters, plus this checkout if it isn't parked yet, counting per key
    /// no more than that key's remaining `maxPerHost` room -- minus
    /// evictions already under way. The room appears as each close
    /// completes, and `closeFinished()` then admits the oldest waiter, so
    /// the caller parks meanwhile. Evictions run in parallel, and a slow
    /// unrelated close (say, a TLS close_notify to an unresponsive peer)
    /// doesn't stop them. (Idle connections for `key` itself never get
    /// here: a checkout reuses them first.) Reusing an idle connection
    /// never needs room -- it doesn't open one.
    private func makeRoomForNewConnection(to key: Key, isNewCheckout: Bool = false, state: inout State) -> Bool {
        guard state.activeCount[key, default: 0] < configuration.maxPerHost else { return false }
        if state.totalOpen < configuration.maxTotal { return true }
        // Per key, only as many checkouts as its `maxPerHost` room allows
        // can ever be admitted, so evicting for more would only destroy
        // other hosts' idle connections.
        var demand = 0
        var countedThisKey = false
        for (waitingKey, list) in state.waiters {
            let room = configuration.maxPerHost - state.activeCount[waitingKey, default: 0]
            guard room > 0 else { continue }
            let extra = isNewCheckout && waitingKey == key ? 1 : 0
            if waitingKey == key { countedThisKey = true }
            demand += min(list.count + extra, room)
        }
        if isNewCheckout, !countedThisKey { demand += 1 }
        while state.evicting < demand, evictOldestIdle(state: &state) {}
        return false
    }

    private func evictOldestIdle(state: inout State) -> Bool {
        var oldest: (key: Key, returnedAt: DispatchTime)?
        for (key, list) in state.idle {
            if let first = list.first, first.returnedAt < oldest?.returnedAt ?? .distantFuture {
                oldest = (key, first.returnedAt)
            }
        }
        guard let key = oldest?.key, var list = state.idle[key] else { return false }
        state.beginClosing(list.removeFirst().connection, isEviction: true)
        state.idle[key] = list.isEmpty ? nil : list
        return true
    }

    private func popValidatedIdle(_ key: Key, state: inout State) -> SMTPConnection? {
        guard var list = state.idle[key], !list.isEmpty else { return nil }
        var result: SMTPConnection?
        while !list.isEmpty {
            let entry = list.removeFirst()
            let ageNanoseconds = DispatchTime.now().uptimeNanoseconds &- entry.returnedAt.uptimeNanoseconds
            let ageSeconds = TimeInterval(ageNanoseconds) / 1_000_000_000
            if ageSeconds > configuration.idleTimeout || !entry.connection.channel.isActive {
                state.beginClosing(entry.connection)
                continue
            }
            result = entry.connection
            break
        }
        state.idle[key] = list.isEmpty ? nil : list
        return result
    }

    /// Settles parked waiters after capacity frees up or a breaker opens.
    /// Waiters whose key's breaker is open fail with `.circuitOpen` (a
    /// fresh checkout would too, and admitting them would only queue up
    /// doomed dials against a host just seen failing). Then freed capacity
    /// is reserved for the oldest remaining waiters -- across all keys, by
    /// arrival order -- whose key `maxPerHost`/`maxTotal` allow; each
    /// admitted waiter dials for itself.
    private func admitWaiters(state: inout State, effects: inout Effects) {
        for key in Array(state.waiters.keys) where isBreakerOpen(key, state: &state) {
            for waiter in state.waiters.removeValue(forKey: key) ?? [] {
                effects.resumes.append((waiter.continuation, .failure(SMTPError.circuitOpen)))
            }
        }
        while true {
            // The oldest waiter (smallest id) among keys under maxPerHost.
            var oldest: (key: Key, id: UInt64)?
            for (key, list) in state.waiters where state.activeCount[key, default: 0] < configuration.maxPerHost {
                if let first = list.first, first.id < oldest?.id ?? .max { oldest = (key, first.id) }
            }
            guard let key = oldest?.key, var list = state.waiters[key],
                  makeRoomForNewConnection(to: key, state: &state)
            else { return }
            let waiter = list.removeFirst()
            state.waiters[key] = list.isEmpty ? nil : list
            state.activeCount[key, default: 0] += 1
            effects.resumes.append((waiter.continuation, .success(.dialYourself)))
        }
    }

    // MARK: - Release

    private func release(_ key: Key, connection: SMTPConnection, healthy: Bool) {
        let effects = lockedEffects { state, effects in
            // Milestone review finding (correctness): a connection released
            // after `shutdown()` has already run must not be appended to
            // `idle[key]` -- `shutdown()` only closes/drains what's *already*
            // idle/parked at the moment it runs, and nothing ever pops/closes
            // an entry added afterward, leaking the connection (and its
            // socket) for the lifetime of the process. Close it immediately
            // instead.
            guard !state.isShutDown else {
                state.beginClosing(connection)
                return
            }
            if healthy, connection.channel.isActive {
                recordSuccess(key, state: &state)
                if var list = state.waiters[key], !list.isEmpty {
                    // The live connection (and its slot) goes straight to
                    // the oldest waiter for this key.
                    let waiter = list.removeFirst()
                    state.waiters[key] = list.isEmpty ? nil : list
                    effects.resumes.append((waiter.continuation, .success(.connection(connection))))
                    return
                }
                state.releaseSlot(key)
                state.idle[key, default: []].append(IdleEntry(connection: connection, returnedAt: DispatchTime.now()))
            } else {
                if !healthy { recordFailure(key, state: &state) } else { recordSuccess(key, state: &state) }
                state.beginClosing(connection)
                state.releaseSlot(key)
            }
            admitWaiters(state: &state, effects: &effects)
            return
        }
        run(effects)
    }

    /// Reserved slots and parked waiters across all keys, for tests that
    /// check nothing is left behind.
    func snapshotForTesting() -> (active: Int, idle: Int, waiters: Int) {
        state.withLockedValue { state in
            (state.totalActive, state.totalIdle, state.waiters.values.reduce(0) { $0 + $1.count })
        }
    }

    // MARK: - Circuit breaker (co-located, plan §4.4)

    /// `true` while `key`'s breaker is open; an expired open breaker is
    /// reset to closed here (the next attempt is the trial).
    private func isBreakerOpen(_ key: Key, state: inout State) -> Bool {
        guard case .open(let until) = state.breaker[key] else { return false }
        if DispatchTime.now() >= until {
            state.breaker[key] = .closed(consecutiveFailures: 0)
            return false
        }
        return true
    }

    private func recordFailure(_ key: Key, state: inout State) {
        let current: Int
        switch state.breaker[key] ?? .closed(consecutiveFailures: 0) {
        case .closed(let n):
            current = n
        case .open:
            // A failure from an attempt that started before the breaker
            // opened keeps it open, for a fresh reset timeout. (The actor
            // version reset an open breaker to `.closed(1)` here, so a run
            // of failures kept re-closing it.)
            state.breaker[key] = .open(until: Self.dispatchDeadline(secondsFromNow: configuration.circuitBreakerResetTimeout))
            return
        }
        let next = current + 1
        state.breaker[key] = next >= configuration.circuitBreakerThreshold
            ? .open(until: Self.dispatchDeadline(secondsFromNow: configuration.circuitBreakerResetTimeout))
            : .closed(consecutiveFailures: next)
    }

    private func recordSuccess(_ key: Key, state: inout State) {
        state.breaker[key] = .closed(consecutiveFailures: 0)
    }
}

// MARK: - `[DeliveryResult]`-shaped `withConnection` health heuristic

extension SMTPConnectionPool {
    /// The `isHealthy` argument every `withConnection(to:isHealthy:_:)`
    /// caller whose `body` returns `[DeliveryResult]` should pass
    /// (`RelayTransport.send`, `DirectMXTransport.attemptOnHost`) -- the
    /// shared layer both transports' message-level-rejection handling
    /// funnels through, so this fix applies uniformly rather than being
    /// special-cased in just one of them (both share this same
    /// `withConnection`-wrapping shape: catch/return a message-level
    /// rejection as data instead of a thrown error, exactly the pattern
    /// that made the connection's actual post-transaction health invisible
    /// to `release` before this fix).
    ///
    /// A connection is *not* healthy when any recipient's outcome is:
    ///   - `.ambiguous` -- a mid-DATA disconnect (plan §4.8's point of no
    ///     return); the connection may already be half-closed and must
    ///     never be assumed alive.
    ///   - `.queuedForRetry` carrying a `421` reply (RFC 5321 §4.2.1's
    ///     "service unavailable, closing the transmission channel") --
    ///     the peer's own explicit statement that it is tearing the
    ///     connection down, regardless of which phase (MAIL FROM, RCPT,
    ///     or the DATA-terminating reply) it arrived in.
    /// Every other outcome (`.delivered`, `.permanentlyFailed`, any other
    /// `.queuedForRetry`, `.expired`, `.failed`) leaves the connection
    /// itself unaffected -- a `550` from a live, correctly-responding peer
    /// is a message-level rejection, not a connection problem.
    public static func deliveryResultsIndicateHealthyConnection(_ results: [DeliveryResult]) -> Bool {
        !results.contains { $0.outcome.indicatesConnectionMayBeUnhealthy }
    }
}

private extension DeliveryResult.Outcome {
    var indicatesConnectionMayBeUnhealthy: Bool {
        switch self {
        case .ambiguous:
            return true
        case .queuedForRetry(_, _, let last):
            return last.code == 421
        case .delivered, .permanentlyFailed, .expired, .failed:
            return false
        }
    }
}

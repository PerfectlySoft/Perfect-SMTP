//
//  SMTPConnectionPoolTests.swift
//  PerfectSMTPTests
//
//  Plan §4.4/§5: cancellation (a `Task` cancelled while parked waiting for
//  a connection slot resolves with `CancellationError`, removed from the
//  waiter queue, no double-resume against a concurrent `release()`) and
//  reentrancy (concurrent checkouts under `maxPerHost` don't overshoot the
//  cap).
//

import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import PerfectSMTP

struct SMTPConnectionPoolTests {
    private let key = SMTPConnectionPool.Key(host: "smtp.example.com", port: 587, tls: .none)

    /// Builds a pool with an injectable dialer that never touches a real
    /// socket: each dial creates a lightweight in-memory `SMTPConnection`
    /// backed by its own `NIOAsyncTestingChannel`, after an artificial
    /// delay/gate the test controls.
    private func makePool(
        maxPerHost: Int,
        onDial: @escaping @Sendable () async -> Void = {}
    ) -> SMTPConnectionPool {
        SMTPConnectionPool(
            configuration: .init(maxPerHost: maxPerHost, maxTotal: 100),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                await onDial()
                let (connection, _) = try await ConnectionHarness.make()
                return connection
            }
        )
    }

    @Test func reentrantCheckoutsDoNotOvershootMaxPerHost() async throws {
        let dialGate = DialGate()
        let pool = makePool(maxPerHost: 1) {
            await dialGate.recordDialStartAndWaitForRelease()
        }

        // Race two checkouts against a pool capped at 1 connection for
        // this host. Reentrancy discipline (plan §4.4) requires the
        // capacity check + reservation to happen synchronously, before the
        // first `await`, under the same lock acquisition -- so only one
        // dial should ever be in flight at a time.
        async let first: Void = pool.withConnection(to: key) { _ in
            try await Task.sleep(nanoseconds: UInt64(50) * 1_000_000)
        }
        async let second: Void = pool.withConnection(to: key) { _ in
            try await Task.sleep(nanoseconds: UInt64(50) * 1_000_000)
        }

        // Give both tasks a chance to reach `checkout`.
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000)
        #expect(await dialGate.concurrentDialCount <= 1)
        await dialGate.release()

        _ = try await (first, second)
        #expect(await dialGate.maxObservedConcurrentDials == 1)

        await pool.shutdown()
    }

    @Test func cancelledWaiterResolvesWithCancellationErrorAndIsRemovedFromQueue() async throws {
        let releaseGate = ManualGate()
        let pool = makePool(maxPerHost: 1)

        // Occupy the only slot for a controlled duration.
        let holderTask = Task {
            try await pool.withConnection(to: key) { _ in
                await releaseGate.wait()
            }
        }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // let the holder actually check out

        // Park a second checkout as a waiter, then cancel it before the
        // slot ever frees up.
        let waiterTask = Task {
            try await pool.withConnection(to: key) { _ in () }
        }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // let it park as a waiter
        waiterTask.cancel()

        let waiterResult = await waiterTask.result
        guard case .failure(let error) = waiterResult, error is CancellationError else {
            Issue.record("expected CancellationError, got \(waiterResult)")
            await releaseGate.open()
            _ = await holderTask.result
            return
        }

        // Now free the slot. A third checkout must succeed promptly --
        // proving the cancelled waiter was actually removed from the
        // queue (not left parked forever, and not double-resumed when the
        // holder's release() runs next).
        await releaseGate.open()
        _ = await holderTask.result

        try await pool.withConnection(to: key) { _ in () }
        await pool.shutdown()
    }

    // MARK: - Lost wakeups: freed capacity must reach a parked waiter

    @Test(.timeLimit(.minutes(1)))
    func aFailedDialHandsItsReservedSlotToAParkedWaiter() async throws {
        // maxPerHost 1: the first checkout reserves the only slot and its
        // dial is held open, so the second checkout parks. When that first
        // dial then fails, the freed slot has to go to the parked waiter;
        // otherwise it waits for a release that will never come.
        let firstDialGate = ManualGate()
        let dials = DialCounter()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 1, maxTotal: 100),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                if await dials.next() == 1 {
                    await firstDialGate.wait()
                    throw SimulatedDialFailure()
                }
                let (connection, _) = try await ConnectionHarness.make()
                return connection
            }
        )

        let first = Task { try await pool.withConnection(to: key) { _ in () } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // first is dialing
        let second = Task { try await pool.withConnection(to: key) { _ in () } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // second is parked
        await firstDialGate.open()

        await #expect(throws: SimulatedDialFailure.self) { try await first.value }
        let secondFinished = await finishesWithin(seconds: 2, second)
        #expect(secondFinished, "the parked waiter never got the slot the failed dial freed")
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func capacityFreedUnderMaxTotalReachesAWaiterForAnotherHost() async throws {
        // maxTotal 1 across two hosts: a checkout for host B parks because
        // host A holds the only slot overall. When A's connection goes back
        // to idle, B's waiter has to be admitted even though no host-B
        // connection was ever released.
        let releaseA = ManualGate()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 4, maxTotal: 1),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                let (connection, _) = try await ConnectionHarness.make()
                return connection
            }
        )
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        let holderA = Task { try await pool.withConnection(to: key) { _ in await releaseA.wait() } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // A holds the only slot
        let waiterB = Task { try await pool.withConnection(to: keyB) { _ in () } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000) // B is parked
        await releaseA.open()
        try await holderA.value

        let waiterFinished = await finishesWithin(seconds: 2, waiterB)
        #expect(waiterFinished, "host B's waiter stayed parked after maxTotal capacity freed up")
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func aWaiterThatIsAlreadyCancelledFailsWithoutParking() async throws {
        let releaseGate = ManualGate()
        let pool = makePool(maxPerHost: 1)
        let holder = Task { try await pool.withConnection(to: key) { _ in await releaseGate.wait() } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000)

        let waiter = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await pool.withConnection(to: key) { _ in () }
        }
        let result = await waiter.result
        guard case .failure(let error) = result, error is CancellationError else {
            Issue.record("expected CancellationError, got \(result)")
            await releaseGate.open()
            _ = await holder.result
            return
        }

        await releaseGate.open()
        try await holder.value
        // The slot must be free again: nothing was left registered for the
        // cancelled waiter to receive.
        let finished = await finishesWithin(seconds: 2, Task { try await pool.withConnection(to: key) { _ in () } })
        #expect(finished)
        await pool.shutdown()
    }

    @Test func shutdownFailsParkedWaitersAndLaterCheckouts() async throws {
        let releaseGate = ManualGate()
        let pool = makePool(maxPerHost: 1)
        let holder = Task { try await pool.withConnection(to: key) { _ in await releaseGate.wait() } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000)
        let waiter = Task { try await pool.withConnection(to: key) { _ in () } }
        try await Task.sleep(nanoseconds: UInt64(20) * 1_000_000)

        await pool.shutdown()

        await #expect(throws: SMTPConnectionPool.PoolError.shutdown) { try await waiter.value }
        await #expect(throws: SMTPConnectionPool.PoolError.shutdown) {
            try await pool.withConnection(to: key) { _ in () }
        }
        await releaseGate.open()
        try await holder.value
    }

    @Test(.timeLimit(.minutes(1)))
    func parkedWaitersFailFastWhenTheirHostsBreakerOpens() async throws {
        // maxPerHost 1, breaker threshold 2, and a host whose dials always
        // fail. Once the breaker opens, the parked waiters must get
        // `.circuitOpen` -- not be admitted one by one to dial a host that
        // was just seen failing -- and the breaker must stay open.
        let dials = DialCounter()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 1, maxTotal: 100, circuitBreakerThreshold: 2, circuitBreakerResetTimeout: 60),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                _ = await dials.next()
                try await Task.sleep(nanoseconds: UInt64(10) * 1_000_000)
                throw SimulatedDialFailure()
            }
        )

        let tasks = (0..<8).map { _ in Task { try await pool.withConnection(to: key) { _ in () } } }
        var circuitOpen = 0
        for task in tasks {
            if case .failure(let error) = await task.result, case SMTPError.circuitOpen = error { circuitOpen += 1 }
        }

        // Two dials open the breaker (threshold 2); everyone else fails fast.
        #expect(await dials.count == 2)
        #expect(circuitOpen == 6)
        let later = await Task { try await pool.withConnection(to: key) { _ in () } }.result
        guard case .failure(let laterError) = later, case SMTPError.circuitOpen = laterError else {
            Issue.record("expected circuitOpen for a checkout after the breaker opened, got \(later)")
            return
        }
        #expect(await dials.count == 2, "a checkout after the breaker opened still dialed")
        await pool.shutdown()
    }

    /// Stress test for the park / hand-off / cancel paths: tasks over three
    /// hosts with tiny caps, connected channels (so healthy releases hand a
    /// live connection over or go idle), a share of unhealthy releases (the
    /// slot is handed over as "dial it yourself"), and cancellations at
    /// random moments (before parking, or while parked). Every task must
    /// finish, the per-host cap must hold, and after each round no slot or
    /// waiter may be left behind.
    @Test(.timeLimit(.minutes(1)))
    func parkHandOffAndCancelUnderContentionNeverLeaksOrOvershoots() async throws {
        let inUse = InUseTracker()
        let keepAlive = ConnectionKeeper()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 2, maxTotal: 4),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                await Task.yield()
                let (connection, channel) = try await ConnectionHarness.make()
                try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
                // Dropping a connection whose channel is still open trips
                // NIOAsyncWriter's "deinited without calling finish()"
                // check; keep every dialed one alive for the test.
                await keepAlive.keep(connection)
                return connection
            }
        )
        let keys = ["a", "b", "c"].map { SMTPConnectionPool.Key(host: "\($0).example.com", port: 587, tls: .none) }

        for round in 0..<30 {
            var tasks: [Task<Void, Error>] = []
            for i in 0..<45 {
                let key = keys[i % 3]
                let healthy = i % 5 != 0
                let task = Task {
                    _ = try await pool.withConnection(to: key, isHealthy: { (_: Bool) in healthy }) { _ in
                        await inUse.enter(key)
                        await Task.yield()
                        await inUse.exit(key)
                        return true
                    }
                }
                tasks.append(task)
                if i % 6 == 2 {
                    let delay = UInt64.random(in: 0...300_000)
                    Task {
                        try? await Task.sleep(nanoseconds: delay)
                        task.cancel()
                    }
                }
            }
            for task in tasks { _ = await task.result }

            let snapshot = pool.snapshotForTesting()
            #expect(snapshot.active == 0, "round \(round): \(snapshot.active) slots still reserved")
            #expect(snapshot.waiters == 0, "round \(round): \(snapshot.waiters) waiters still parked")
            #expect(await inUse.maxObserved <= 2, "round \(round): per-host cap exceeded")
        }
        await pool.shutdown()
    }
}

private struct SimulatedDialFailure: Error {}

private actor DialCounter {
    private(set) var count = 0
    func next() -> Int {
        count += 1
        return count
    }
}

private actor ConnectionKeeper {
    private var connections: [SMTPConnection] = []
    func keep(_ connection: SMTPConnection) { connections.append(connection) }
}

private actor InUseTracker {
    private var current: [SMTPConnectionPool.Key: Int] = [:]
    private(set) var maxObserved = 0
    func enter(_ key: SMTPConnectionPool.Key) {
        current[key, default: 0] += 1
        maxObserved = max(maxObserved, current[key]!)
    }
    func exit(_ key: SMTPConnectionPool.Key) {
        current[key, default: 0] -= 1
    }
}

/// `true` if `task` finishes (returning or throwing) within `seconds`;
/// otherwise cancels it and returns `false`. Keeps a lost-wakeup regression
/// from hanging the whole suite.
private func finishesWithin(seconds: Double, _ task: Task<Void, any Error>) async -> Bool {
    let timeout = Task {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        return !Task.isCancelled
    }
    let watcher = Task {
        _ = await task.result
        timeout.cancel()
    }
    let timedOut = await timeout.value
    if timedOut { task.cancel() }
    await watcher.value
    return !timedOut
}

/// Gates a controlled number of concurrent "dial" calls so the reentrancy
/// test can assert on how many were ever in flight simultaneously, and
/// release them all at once on command. `@unchecked Sendable`: all access
/// is behind the actor.
private actor DialGate {
    private(set) var concurrentDialCount = 0
    private(set) var maxObservedConcurrentDials = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var released = false

    func recordDialStartAndWaitForRelease() async {
        concurrentDialCount += 1
        maxObservedConcurrentDials = max(maxObservedConcurrentDials, concurrentDialCount)
        if released {
            concurrentDialCount -= 1
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
        concurrentDialCount -= 1
    }

    func release() {
        released = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

/// A simple open-once gate for coordinating test task ordering.
private actor ManualGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

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
        let sockets = OpenSocketTracker()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 2, maxTotal: 4),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                await Task.yield()
                let (connection, channel) = try await ConnectionHarness.make()
                try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
                sockets.opened(channel)
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
            #expect(await inUse.maxObservedTotal <= 4, "round \(round): maxTotal exceeded by connections in use")
            #expect(sockets.maxOpen <= 4, "round \(round): \(sockets.maxOpen) connections open at once, over maxTotal")
        }
        await pool.shutdown()
    }

    // MARK: - maxTotal counts idle connections too

    @Test(.timeLimit(.minutes(1)))
    func anIdleConnectionForOneHostIsClosedToMakeRoomForAnother() async throws {
        // maxTotal 1: host A's connection goes back to idle, so it still
        // holds the only slot. A checkout for host B must close it and
        // dial, not open a second connection (and not wait for A's idle
        // timeout, which is only checked on A's own checkouts).
        let sockets = OpenSocketTracker()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 4, maxTotal: 1),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                let (connection, channel) = try await ConnectionHarness.make()
                try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
                sockets.opened(channel)
                return connection
            }
        )
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        try await pool.withConnection(to: key) { _ in () }
        #expect(sockets.currentOpen == 1)

        let finished = await finishesWithin(seconds: 2, Task { try await pool.withConnection(to: keyB) { _ in () } })
        #expect(finished, "host B's checkout didn't complete")
        #expect(sockets.maxOpen == 1, "\(sockets.maxOpen) connections were open at once with maxTotal 1")
        #expect(sockets.currentOpen == 1)
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func reusingAnIdleConnectionNeverPutsMoreThanMaxTotalInUse() async throws {
        // maxTotal 2. Host A leaves a connection idle; host B then holds
        // two connections, which has to evict A's idle one. A checkout for
        // A must now wait -- previously it reused its idle connection,
        // putting three in use at once.
        let sockets = OpenSocketTracker()
        let releaseB = ManualGate()
        let pool = SMTPConnectionPool(
            configuration: .init(maxPerHost: 2, maxTotal: 2),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                let (connection, channel) = try await ConnectionHarness.make()
                try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
                sockets.opened(channel)
                return connection
            }
        )
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        try await pool.withConnection(to: key) { _ in () }
        let holdersB = (0..<2).map { _ in Task { try await pool.withConnection(to: keyB) { _ in await releaseB.wait() } } }
        try await waitForPool(pool) { $0.active == 2 }

        let checkoutA = Task { try await pool.withConnection(to: key) { _ in () } }
        // A's checkout has to park: B holds both of maxTotal's slots and
        // nothing is idle any more.
        try await waitForPool(pool) { $0.waiters == 1 }
        let parked = pool.snapshotForTesting()
        #expect(parked.waiters == 1 && parked.active == 2 && parked.idle == 0,
                "expected host A's checkout parked behind host B's two connections, got \(parked)")
        #expect(sockets.maxOpen <= 2, "\(sockets.maxOpen) connections were open at once with maxTotal 2")

        await releaseB.open()
        for holder in holdersB { try await holder.value }
        let finished = await finishesWithin(seconds: 2, checkoutA)
        #expect(finished, "host A's checkout never got a slot back")
        #expect(sockets.maxOpen <= 2)
        await pool.shutdown()
    }


    // MARK: - A close that takes time still counts toward maxTotal

    /// A pool whose connections hold `close()` until `holder` releases it,
    /// like NIOSSL waiting for the peer's close_notify.
    private func makeSlowClosingPool(
        _ configuration: SMTPConnectionPool.Configuration, sockets: OpenSocketTracker, holder: CloseHolder,
        slowKeys: Set<SMTPConnectionPool.Key>? = nil
    ) -> SMTPConnectionPool {
        SMTPConnectionPool(configuration: configuration, group: NIOAsyncTestingEventLoop(), dialer: { key in
            let (connection, channel) = try await ConnectionHarness.make()
            if slowKeys?.contains(key) ?? true {
                try await channel.testingEventLoop.executeInContext {
                    try channel.pipeline.syncOperations.addHandler(HoldCloseHandler(holder), position: .first)
                }
            }
            try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 25))
            sockets.opened(channel)
            return connection
        })
    }

    @Test(.timeLimit(.minutes(1)))
    func aClosingConnectionKeepsItsMaxTotalSlotUntilTheCloseCompletes() async throws {
        // maxTotal 1: host A's connection is released unhealthy and starts
        // closing, but the close is held. A checkout for host B must wait
        // for it instead of opening a second socket.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let pool = makeSlowClosingPool(.init(maxPerHost: 4, maxTotal: 1), sockets: sockets, holder: holder)
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        _ = try? await pool.withConnection(to: key) { _ in throw SimulatedDialFailure() }
        let checkoutB = Task { try await pool.withConnection(to: keyB) { _ in () } }
        try await waitForPool(pool) { $0.waiters == 1 }
        #expect(pool.snapshotForTesting().waiters == 1, "host B's checkout didn't wait for the close")
        #expect(sockets.maxOpen == 1, "\(sockets.maxOpen) connections were open at once with maxTotal 1")

        holder.releaseAll()
        #expect(await finishesWithin(seconds: 2, checkoutB), "host B's checkout wasn't admitted once the close completed")
        #expect(sockets.maxOpen == 1)
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func aStaleIdleConnectionReapedOnReuseStillCountsUntilItHasClosed() async throws {
        // maxTotal 2, idleTimeout 50 ms. Host A has a stale idle connection
        // and a fresh one; A's next checkout reaps the stale one (its close
        // is held) and reuses the fresh one. Host B must then wait, not
        // dial a third socket.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let pool = makeSlowClosingPool(.init(maxPerHost: 4, maxTotal: 2, idleTimeout: 0.05), sockets: sockets, holder: holder)
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        let first = ManualGate(), second = ManualGate()
        let holder1 = Task { try await pool.withConnection(to: key) { _ in await first.wait() } }
        let holder2 = Task { try await pool.withConnection(to: key) { _ in await second.wait() } }
        try await waitForPool(pool) { $0.active == 2 }
        await first.open()
        try await holder1.value
        try await Task.sleep(nanoseconds: 100_000_000) // the first connection is now stale
        await second.open()
        try await holder2.value // the second goes idle fresh

        let keepA = ManualGate()
        let checkoutA = Task { try await pool.withConnection(to: key) { _ in await keepA.wait() } }
        try await waitForPool(pool) { $0.active == 1 && $0.idle == 0 }
        let checkoutB = Task { try await pool.withConnection(to: keyB) { _ in () } }
        try await waitForPool(pool) { $0.waiters == 1 }
        #expect(pool.snapshotForTesting().waiters == 1, "host B's checkout didn't wait for the stale connection to close")
        #expect(sockets.maxOpen <= 2, "\(sockets.maxOpen) connections were open at once with maxTotal 2")

        holder.releaseAll()
        #expect(await finishesWithin(seconds: 2, checkoutB))
        await keepA.open()
        try await checkoutA.value
        #expect(sockets.maxOpen <= 2)
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func aCheckoutWaitingForAnEvictionCanBeCancelled() async throws {
        // maxTotal 1: host B's checkout evicts host A's idle connection,
        // whose close is held, so B waits. Cancelling B must end it with
        // CancellationError without dialing, and leave the slot free.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let pool = makeSlowClosingPool(.init(maxPerHost: 4, maxTotal: 1), sockets: sockets, holder: holder)
        let keyB = SMTPConnectionPool.Key(host: "other.example.com", port: 587, tls: .none)

        try await pool.withConnection(to: key) { _ in () }
        let checkoutB = Task { try await pool.withConnection(to: keyB) { _ in () } }
        try await waitForPool(pool) { $0.waiters == 1 }
        checkoutB.cancel()
        let result = await checkoutB.result
        guard case .failure(let error) = result, error is CancellationError else {
            Issue.record("expected CancellationError, got \(result)")
            holder.releaseAll()
            await pool.shutdown()
            return
        }
        #expect(sockets.dials == 1, "the cancelled checkout dialed anyway")

        holder.releaseAll()
        try await waitForPool(pool) { $0.active == 0 && $0.waiters == 0 }
        #expect(await finishesWithin(seconds: 2, Task { try await pool.withConnection(to: keyB) { _ in () } }))
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func aSlowUnrelatedCloseDoesNotStopEvictionForAWaitingCheckout() async throws {
        // maxTotal 2: host A's connection is idle (closes quickly); host
        // B's was released unhealthy and its close is held, like a TLS
        // close_notify to an unresponsive peer. A checkout for host C must
        // evict A's idle connection and proceed, not wait for B's close.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let keyB = SMTPConnectionPool.Key(host: "b.example.com", port: 587, tls: .none)
        let keyC = SMTPConnectionPool.Key(host: "c.example.com", port: 587, tls: .none)
        let pool = makeSlowClosingPool(.init(maxPerHost: 4, maxTotal: 2), sockets: sockets, holder: holder, slowKeys: [keyB])

        try await pool.withConnection(to: key) { _ in () }
        _ = try? await pool.withConnection(to: keyB) { _ in throw SimulatedDialFailure() }
        #expect(await finishesWithin(seconds: 2, Task { try await pool.withConnection(to: keyC) { _ in () } }),
                "host C's checkout waited for host B's slow close instead of evicting host A's idle connection")
        #expect(sockets.maxOpen <= 2)

        holder.releaseAll()
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func evictionsForSeveralWaitingCheckoutsRunInParallel() async throws {
        // maxTotal 3, three hosts' connections idle, all closes held.
        // Checkouts for three other hosts must start three evictions at
        // once, not one after another.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let pool = makeSlowClosingPool(.init(maxPerHost: 4, maxTotal: 3), sockets: sockets, holder: holder)
        let idleKeys = ["a", "b", "c"].map { SMTPConnectionPool.Key(host: "\($0).example.com", port: 587, tls: .none) }
        let newKeys = ["d", "e", "f"].map { SMTPConnectionPool.Key(host: "\($0).example.com", port: 587, tls: .none) }

        for idleKey in idleKeys { try await pool.withConnection(to: idleKey) { _ in () } }
        let checkouts = newKeys.map { newKey in Task { try await pool.withConnection(to: newKey) { _ in () } } }
        try await waitForPool(pool) { $0.waiters == 3 }
        try await waitUntilHeld(holder, count: 3)
        #expect(holder.heldCount == 3, "\(holder.heldCount) evictions started for 3 waiting checkouts")

        holder.releaseAll()
        for checkout in checkouts {
            #expect(await finishesWithin(seconds: 2, checkout))
        }
        #expect(sockets.maxOpen <= 3)
        await pool.shutdown()
    }

    @Test(.timeLimit(.minutes(1)))
    func evictionIsCappedByTheWaitingHostsPerHostRoom() async throws {
        // maxPerHost 2, maxTotal 4: three other hosts' connections are idle
        // and host A already has one connection checked out. Three more
        // checkouts for A: maxPerHost leaves room for only one of them, so
        // exactly one idle connection may be evicted -- not three.
        let sockets = OpenSocketTracker()
        let holder = CloseHolder()
        let pool = makeSlowClosingPool(.init(maxPerHost: 2, maxTotal: 4), sockets: sockets, holder: holder)
        let idleKeys = ["x", "y", "z"].map { SMTPConnectionPool.Key(host: "\($0).example.com", port: 587, tls: .none) }

        for idleKey in idleKeys { try await pool.withConnection(to: idleKey) { _ in () } }
        let keepA = ManualGate()
        let holderA = Task { try await pool.withConnection(to: key) { _ in await keepA.wait() } }
        try await waitForPool(pool) { $0.active == 1 }
        let checkouts = (0..<3).map { _ in Task { try await pool.withConnection(to: key) { _ in () } } }
        try await waitForPool(pool) { $0.waiters == 3 }
        try await Task.sleep(nanoseconds: 20_000_000)

        #expect(holder.heldCount == 1, "\(holder.heldCount) idle connections evicted; only 1 checkout for host A can be admitted")
        #expect(pool.snapshotForTesting().idle == 2)

        holder.releaseAll()
        await keepA.open()
        try await holderA.value
        for checkout in checkouts {
            #expect(await finishesWithin(seconds: 2, checkout))
        }
        #expect(sockets.maxOpen <= 4)
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

private actor InUseTracker {
    private var current: [SMTPConnectionPool.Key: Int] = [:]
    private var currentTotal = 0
    private(set) var maxObserved = 0
    private(set) var maxObservedTotal = 0
    func enter(_ key: SMTPConnectionPool.Key) {
        current[key, default: 0] += 1
        currentTotal += 1
        maxObserved = max(maxObserved, current[key]!)
        maxObservedTotal = max(maxObservedTotal, currentTotal)
    }
    func exit(_ key: SMTPConnectionPool.Key) {
        current[key, default: 0] -= 1
        currentTotal -= 1
    }
}

/// Counts dialed connections that are still open, independent of the
/// pool's own bookkeeping: each dialed channel counts until its close
/// future fires.
private final class OpenSocketTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var open = 0
    private var maxSeen = 0
    private var dialed = 0

    var currentOpen: Int { lock.withLock { open } }
    var maxOpen: Int { lock.withLock { maxSeen } }
    var dials: Int { lock.withLock { dialed } }

    func opened(_ channel: any Channel) {
        lock.withLock {
            open += 1
            dialed += 1
            maxSeen = max(maxSeen, open)
        }
        channel.closeFuture.whenComplete { _ in self.lock.withLock { self.open -= 1 } }
    }
}

/// Holds every outbound `close()` until `releaseAll()`, standing in for a
/// TLS close waiting on the peer's close_notify.
private final class CloseHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var held: [(any EventLoop, () -> Void)] = []
    private var heldChannels: Set<ObjectIdentifier> = []
    private var holding = true

    func hold(_ channel: any Channel, _ close: @escaping () -> Void) {
        let runNow: Bool = lock.withLock {
            guard holding else { return true }
            held.append((channel.eventLoop, close))
            heldChannels.insert(ObjectIdentifier(channel))
            return false
        }
        if runNow { close() }
    }

    /// Distinct channels with a close held (a channel can get more than
    /// one `close()` call).
    var heldCount: Int { lock.withLock { heldChannels.count } }

    func releaseAll() {
        let released: [(any EventLoop, () -> Void)] = lock.withLock {
            holding = false
            defer { held = [] }
            return held
        }
        for (eventLoop, close) in released { eventLoop.execute(close) }
    }
}

private final class HoldCloseHandler: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = NIOAny
    private let holder: CloseHolder
    init(_ holder: CloseHolder) { self.holder = holder }

    func close(context: ChannelHandlerContext, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        holder.hold(context.channel) { context.close(mode: mode, promise: promise) }
    }
}

/// Polls until `holder` holds `count` closes (or 2 s pass).
private func waitUntilHeld(_ holder: CloseHolder, count: Int) async throws {
    let deadline = Date().addingTimeInterval(2)
    while holder.heldCount < count, Date() < deadline {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
}

/// Polls the pool's own counts until `condition` holds (or 2 s pass).
private func waitForPool(
    _ pool: SMTPConnectionPool, _ condition: ((active: Int, idle: Int, waiters: Int)) -> Bool
) async throws {
    let deadline = Date().addingTimeInterval(2)
    while !condition(pool.snapshotForTesting()), Date() < deadline {
        try await Task.sleep(nanoseconds: 1_000_000)
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

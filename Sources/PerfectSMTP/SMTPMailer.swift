//
//  SMTPMailer.swift
//  PerfectSMTP
//
//  Public API (plan §4.9, minus the AsyncSequence-based streaming-send
//  overload, which is Phase 5 scope). Generic over `any SMTPTransport`;
//  the two-phase compose/sign/send pipeline
//  (`MIMEComposer` -> optional `MessageSigner` -> `transport.send`) is the
//  mailer's actual internal implementation, not just a sketch -- `send`
//  is sugar over it.
//

import Foundation
import Logging
import NIOConcurrencyHelpers
import NIOCore

public struct SMTPMailer: Sendable {
    public struct Configuration: Sendable {
        /// Caps in-flight batch-send tasks independent of (and typically
        /// larger than) any transport's own connection-pool cap (plan
        /// §4.9's corrected bounded-batch fan-out).
        public var maxInFlightBatchSends: Int
        public init(maxInFlightBatchSends: Int = 16) {
            self.maxInFlightBatchSends = maxInFlightBatchSends
        }
    }

    private let transport: any SMTPTransport
    /// Pluggable, optional signing step -- Phase 2's `DKIMSigner` conforms
    /// to this (see `PerfectSMTPCore/MessageSigner.swift`). `nil` means
    /// "no DKIM step": the composed `RFC5322Message` is serialized
    /// straight into `SignedMessage.rfc5322` with no signing at all, which
    /// is what makes Phase 1 a fully working mailer on its own.
    private let signer: (any MessageSigner)?
    private let configuration: Configuration
    /// Only ever used for the DKIM DMARC-alignment lint below (plan
    /// §4.6) -- `PerfectSMTPCore` deliberately stays free of a swift-log
    /// dependency (see `DKIMSigner.isAligned(withFromDomain:)`'s doc
    /// comment), so this is the one place in the mailer that actually
    /// emits a log line, kept intentionally narrow in scope.
    private let logger: Logger

    /// - Parameters:
    ///   - transport: The delivery strategy this mailer sends through --
    ///     `RelayTransport`, `LocalMTATransport`, `DirectMXTransport`, or
    ///     any other `SMTPTransport` conformance. Every `send` overload on
    ///     this mailer ultimately calls `transport.send(_:_:)` once per
    ///     message.
    ///   - signer: `nil` (the default) means no DKIM step at all -- the
    ///     composed message is sent unsigned. Pass a `DKIMSigner` (see
    ///     `PerfectSMTPCore/DKIM/DKIMSigner.swift`) to sign every message
    ///     this mailer sends; see `composeAndSign(_:)` for exactly where
    ///     signing happens in the pipeline.
    ///   - configuration: Currently just `maxInFlightBatchSends`, the
    ///     concurrency cap for the batch/streaming `send` overloads below
    ///     -- irrelevant to the single-message `send(_:bcc:envelopeFrom:)`.
    ///   - logger: Used only to log a warning when `signer` is a
    ///     `DKIMSigner` whose `d=` domain doesn't DMARC-align with the
    ///     message's `From:` domain (see `composeAndSign(_:)`) -- this
    ///     mailer never logs anything else. Defaults to a logger labeled
    ///     `"PerfectSMTP.SMTPMailer"`.
    public init(
        transport: any SMTPTransport,
        signer: (any MessageSigner)? = nil,
        configuration: Configuration = .init(),
        logger: Logger = Logger(label: "PerfectSMTP.SMTPMailer")
    ) {
        self.transport = transport
        self.signer = signer
        self.configuration = configuration
        self.logger = logger
    }

    /// Single-message send. `bcc` is supplied separately, never on
    /// `EmailMessage` (Phase 0's structural Bcc-leak fix) -- these
    /// addresses only ever become extra `SMTPEnvelope.recipients` entries,
    /// never a serialized header.
    public func send(
        _ message: EmailMessage,
        bcc: [String] = [],
        envelopeFrom: ReversePath
    ) async throws -> [DeliveryResult] {
        let signed = try composeAndSign(message)
        let recipients = message.to.map(\.address) + message.cc.map(\.address) + bcc
        let envelope = try SMTPEnvelope(mailFrom: envelopeFrom, recipients: recipients, size: signed.estimatedSize)
        return try await transport.send(envelope, signed)
    }

    /// Batch send: one message per `EmailMessage`, each using its own
    /// `to`/`cc` as recipients and a `.null` reverse-path is *not* assumed
    /// -- callers needing a specific envelope-from per message should use
    /// `send(_:bcc:envelopeFrom:)` directly in a loop with their own
    /// concurrency control; this overload exists for the common case of
    /// sending the same shape of message (e.g. a templated batch) to many
    /// independent recipients, each already fully composed as its own
    /// `EmailMessage`, from a shared `envelopeFrom`.
    ///
    /// Uses the sliding-window task-group pattern (plan §4.9's corrected
    /// bounded-batch fan-out): primes `configuration.maxInFlightBatchSends`
    /// children, then adds one new child each time one completes, capping
    /// in-flight tasks independent of the transport's own connection cap
    /// -- never a naive `for msg in messages { group.addTask { ... } }`,
    /// which would launch every child eagerly regardless of capacity.
    ///
    /// **Not all-or-nothing (FIX #5, milestone architecture/concurrency
    /// review, required correction):** the original implementation used
    /// `withThrowingTaskGroup`, so per structured-concurrency semantics any
    /// single child's throw (an envelope-level `MAIL FROM` rejection, a
    /// connection error, a compose/DKIM failure -- as opposed to a
    /// per-recipient rejection, which already correctly becomes a
    /// `DeliveryResult` rather than a throw) cancelled every other in-
    /// flight/pending child and aborted the whole call, discarding all
    /// already-collected results. For a batch API explicitly motivated by
    /// list-server/bulk-mail use (plan §8), one bad message losing every
    /// other good one in the batch is a significant usability gap. Each
    /// child task below catches its own message's error instead and maps
    /// it to a `.failed(error)` `DeliveryResult` per that message's
    /// would-be recipients, so the function no longer needs `throws` at
    /// all: the only pre-flight case (`messages.isEmpty`) already returns
    /// `[]` synchronously rather than throwing, and every other failure
    /// mode is now representable as data in the returned array.
    public func send(_ messages: [EmailMessage], envelopeFrom: ReversePath) async -> [DeliveryResult] {
        guard !messages.isEmpty else { return [] }
        let maxInFlight = max(1, configuration.maxInFlightBatchSends)

        return await withTaskGroup(of: (Int, [DeliveryResult]).self) { group in
            var results = [[DeliveryResult]](repeating: [], count: messages.count)
            var nextIndex = 0

            func addNextTask() {
                guard nextIndex < messages.count else { return }
                let index = nextIndex
                let message = messages[index]
                nextIndex += 1
                group.addTask {
                    do {
                        let sent = try await self.send(message, envelopeFrom: envelopeFrom)
                        return (index, sent)
                    } catch {
                        // This message's own recipients (to + cc -- the
                        // batch overload never takes a per-message `bcc`,
                        // matching `self.send`'s own recipient formula
                        // absent a `bcc` argument), each reported as
                        // `.failed`, so the caller still sees exactly one
                        // outcome per intended recipient rather than the
                        // message vanishing from the results entirely.
                        let recipients = message.to.map(\.address) + message.cc.map(\.address)
                        let failed = recipients.map { DeliveryResult(recipient: $0, outcome: .failed(error)) }
                        return (index, failed)
                    }
                }
            }

            let primeCount = min(maxInFlight, messages.count)
            for _ in 0..<primeCount { addNextTask() }

            while let (index, sent) = await group.next() {
                results[index] = sent
                addNextTask()
            }

            return results.flatMap { $0 }
        }
    }

    // MARK: - Streaming batch send (plan §4.9/§8)

    /// `AsyncSequence`-based streaming overload of the batch `send` above --
    /// added specifically for list-server/bulk-mail use (plan §8): a list
    /// server generating millions of per-recipient messages from a
    /// subscriber database cannot materialize `[EmailMessage]` in memory
    /// first. `messages` is consumed lazily, one element at a time, via its
    /// own `AsyncIterator` -- never `Array(messages)` or any other eager
    /// materialization.
    ///
    /// **Input-side backpressure** matches the array-based `send`'s
    /// already-fixed sliding-window fan-out exactly (plan §4.9's corrected
    /// bounded-batch fan-out): at most `configuration.maxInFlightBatchSends`
    /// messages are ever concurrently being composed/signed/sent at once --
    /// primed up front, then one new message is pulled from `messages` only
    /// when an in-flight send actually completes. A message is never
    /// eagerly pulled off the source sequence just because it's available.
    ///
    /// **Output-side backpressure -- the subtlety this signature alone
    /// doesn't convey, documented here in detail since it's the one place
    /// in this phase a subtle design choice really matters.**
    ///
    /// The obvious-looking approach -- `AsyncThrowingStream`'s
    /// `(stream, continuation) = .makeStream(bufferingPolicy: .bufferingOldest(n))`
    /// construction, with producers calling `continuation.yield` directly
    /// -- was tried first and rejected after checking its actual documented
    /// behavior (verified empirically against this toolchain, not
    /// assumed): `Continuation.yield` is a **synchronous, non-suspending**
    /// call, so no `bufferingPolicy` can make it genuinely wait for the
    /// consumer. `.bufferingNewest`/`.bufferingOldest` bound *memory* by
    /// **silently dropping** elements once the buffer is full, not by
    /// blocking the producer -- confirmed directly: yielding a 3rd element
    /// into a `.bufferingOldest(2)` stream that nobody has read from yet
    /// returns `.dropped(3)`, not a suspension. For a mail-sending API,
    /// silently dropping `DeliveryResult`s is a real correctness bug, not
    /// an acceptable memory/throughput trade-off -- a caller who thinks
    /// they observed every message's outcome but actually missed some to a
    /// full buffer would be actively misled about what was and wasn't
    /// sent. (A first draft of this method used exactly this
    /// continuation-based shape, with a separate always-running relay task
    /// bridging a bounded internal channel to `continuation.yield` -- and
    /// even *that* still silently dropped results under a slow/absent
    /// consumer, because nothing stopped the relay from draining the
    /// internal channel and calling `yield` faster than the consumer
    /// actually read the stream. Recorded here because it's the natural
    /// design to reach for first, and it's subtly wrong.)
    ///
    /// The construction that actually provides blocking (non-dropping)
    /// backpressure is the **pull-based** one:
    /// `AsyncThrowingStream(unfolding:)`. Its `produce` closure is invoked
    /// by the framework only when the consumer's `AsyncIterator.next()` is
    /// actually called, and is never invoked again until the previously
    /// produced element has been handed back to the caller -- there is no
    /// intermediate buffer to overflow at all, so there is nothing to drop.
    /// `produce` here is `try await channel.pull()`, where `channel` is a
    /// small internal lock-protected `ResultChannel` (below) with an explicit,
    /// bounded `capacity` (reusing `configuration.maxInFlightBatchSends` as
    /// that bound -- one small, explicit number governs both the input-side
    /// sliding window and the output-side channel, rather than inventing a
    /// second config field). `ResultChannel.push` is `async` and genuinely
    /// suspends -- never drops -- once the channel is full; every
    /// sliding-window child task calls it once per `DeliveryResult` it
    /// produces, so a full channel stalls those child tasks, which stalls
    /// `group.next()` resolving, which stalls `startNextIfPossible` pulling
    /// the next message off `messages` -- real, composed backpressure all
    /// the way from an unread output stream back to source-sequence
    /// iteration, exactly as required, with a hard, explicit memory bound
    /// and zero silent data loss.
    ///
    /// The one gap `AsyncThrowingStream(unfolding:)` has relative to the
    /// continuation-based construction: it exposes no `onCancel`/
    /// `onTermination` parameter in this Swift toolchain (verified
    /// directly by attempting to pass one -- it fails to compile), so it
    /// can't use the idiom named in the original requirement text
    /// verbatim. This is compensated for below with two independent
    /// mechanisms covering the two distinct ways a consumer can stop
    /// listening (see the "Cancellation" paragraph).
    ///
    /// **Per-message error isolation** matches the array-based `send`'s
    /// FIX #5 exactly: each message's send is attempted inside its own
    /// child task; a thrown failure (compose/DKIM/connection-level -- as
    /// opposed to a per-recipient rejection, which the transport already
    /// reports as data) is caught there and mapped to `.failed(error)`
    /// `DeliveryResult`s for that message's own would-be recipients, pushed
    /// to the channel exactly like a successful send's results would be.
    /// **Single consumer.** Iterate the returned stream from one task only.
    /// `AsyncThrowingStream(unfolding:)` doesn't serialize `next()` across
    /// tasks, and the channel supports one parked reader at a time, so a
    /// second concurrent consumer traps (`precondition`) rather than
    /// silently stranding the first one.
    ///
    /// The returned stream itself only ever terminates by throwing for a
    /// genuinely stream-level failure -- `messages`' own `AsyncIterator`
    /// throwing -- never for an individual message's delivery outcome.
    ///
    /// **Cancellation** covers both cases named in the requirement, via two
    /// independent mechanisms since no single hook on `unfolding` catches
    /// both:
    /// - **The consuming task is cancelled**, possibly while `produce` is
    ///   itself suspended inside `channel.pull()` awaiting the next result.
    ///   `ResultChannel.pull` (like `push`) is wrapped in
    ///   `withTaskCancellationHandler`, so it wakes promptly on the calling
    ///   task's cancellation (the handler removes the parked waiter under
    ///   the channel's lock and resumes it right after) and `produce`
    ///   then cancels `driver` and ends the sequence.
    /// - **The stream/iterator is torn down without being drained** (e.g. a
    ///   consumer that `break`s out of a `for await` loop early, or simply
    ///   never iterates the returned stream at all) -- no task cancellation
    ///   occurs in this case, so the above alone wouldn't catch it. A tiny
    ///   `StreamLifetimeToken`, captured only by the `unfolding` closure
    ///   itself, cancels `driver` from its `deinit` -- the same
    ///   deinit-driven mechanism `AsyncStream`'s own `onTermination` uses
    ///   internally, applied by hand since `unfolding` doesn't expose it as
    ///   a parameter. Once the closure (and therefore the token) is
    ///   released -- which happens when nothing references the stream/
    ///   iterator anymore -- `driver` is cancelled even though no `Task`
    ///   was ever explicitly cancelled.
    ///
    /// Either path cancels `driver`; cancellation then propagates
    /// automatically (plain structured-concurrency semantics) to every
    /// child task in the sliding-window group, including one currently
    /// parked inside `ResultChannel.push`, which is itself cancellation-
    /// aware for the same reason `pull` is. `startNextIfPossible` also
    /// stops advancing `messages`' iterator once cancellation is observed,
    /// so source-sequence iteration halts promptly rather than continuing
    /// in the background indefinitely.
    public func send<S: AsyncSequence>(
        _ messages: S,
        envelopeFrom: ReversePath
    ) -> AsyncThrowingStream<DeliveryResult, Error> where S.Element == EmailMessage, S: Sendable {
        let maxInFlight = max(1, configuration.maxInFlightBatchSends)
        let channel = ResultChannel<DeliveryResult>(capacity: maxInFlight)
        let mailer = self

        // The coordinating task: iterates `messages` lazily, runs the same
        // sliding-window bounded fan-out as the array-based `send`, and
        // pushes every produced `DeliveryResult` into `channel` (which is
        // what actually applies backpressure -- see the doc comment above).
        let driver = Task {
            await withTaskGroup(of: Void.self) { group in
                var iterator = messages.makeAsyncIterator()
                var sourceExhausted = false
                var sourceError: (any Error)?

                func startNextIfPossible() async -> Bool {
                    guard !sourceExhausted, !Task.isCancelled else { return false }
                    let next: EmailMessage?
                    do {
                        next = try await iterator.next()
                    } catch {
                        sourceExhausted = true
                        sourceError = error
                        return false
                    }
                    guard let message = next else {
                        sourceExhausted = true
                        return false
                    }
                    group.addTask {
                        do {
                            let sent = try await mailer.send(message, envelopeFrom: envelopeFrom)
                            for result in sent {
                                await channel.push(result)
                            }
                        } catch {
                            // Same FIX #5 shape as the array-based batch
                            // send: a transport/compose/DKIM-level throw
                            // for this one message becomes a `.failed`
                            // result per its own would-be recipients,
                            // instead of aborting the whole stream.
                            let recipients = message.to.map(\.address) + message.cc.map(\.address)
                            for recipient in recipients {
                                await channel.push(DeliveryResult(recipient: recipient, outcome: .failed(error)))
                            }
                        }
                    }
                    return true
                }

                let primeCount = maxInFlight
                for _ in 0..<primeCount {
                    guard await startNextIfPossible() else { break }
                }

                while await group.next() != nil {
                    _ = await startNextIfPossible()
                }

                channel.finish(throwing: sourceError)
            }
        }

        // See "Cancellation" above: released only when the `unfolding`
        // closure itself is released (stream/iterator abandoned without
        // ever being drained), independent of any `Task` cancellation.
        let lifetimeToken = StreamLifetimeToken { driver.cancel() }

        return AsyncThrowingStream<DeliveryResult, Error>(unfolding: {
            _ = lifetimeToken // kept alive exactly as long as this closure is
            do {
                return try await channel.pull()
            } catch is CancellationError {
                driver.cancel()
                return nil
            }
        })
    }

    // MARK: - Two-phase compose/sign/send (plan §4.9)

    /// Composes `message` and, when a signer is configured, signs it --
    /// the mailer's internal implementation of §4.9's two-phase sketch:
    /// `MIMEComposer(msg, charset:).compose()` -> optional
    /// `signer.sign(...)` -> `transport.send(envelope, signed)`.
    public func composeAndSign(_ message: EmailMessage) throws -> SignedMessage {
        let composed = try MIMEComposer(message).compose()
        let finalMessage: RFC5322Message
        if let signer {
            // Milestone review finding (LassoPerfectSMTP Phase F, protocol
            // pass): a `DKIMSigner` built once (e.g. at server startup)
            // with a fixed `signedHeaders` list has no way to cover
            // `message.extraHeaders`' names, which are a per-message
            // concern -- different `EmailMessage`s may add different
            // custom header names. Widening `signedHeaders` here, right
            // before signing, closes that gap for every caller of
            // `EmailMessage.extraHeaders` + `DKIMSigner`, not just one
            // adapter. Cheap (see `signingAdditionalHeaders`'s doc
            // comment) and a no-op both when there's no `DKIMSigner`
            // configured (a plain `MessageSigner` doesn't get this
            // treatment -- there's no generic protocol-level way to widen
            // an arbitrary signer's covered headers) and when the message
            // has no `extraHeaders` at all.
            let effectiveSigner: any MessageSigner
            if let dkim = signer as? DKIMSigner {
                effectiveSigner = dkim.signingAdditionalHeaders(message.extraHeaders.map(\.name))
            } else {
                effectiveSigner = signer
            }
            finalMessage = try effectiveSigner.sign(composed)
            // DMARC-alignment lint (plan §4.6): a type-check against the
            // concrete `DKIMSigner`, not a `MessageSigner` protocol
            // requirement -- keeping the alignment check itself as pure
            // data on `DKIMSigner` (in the no-swift-log `PerfectSMTPCore`
            // target) and doing the actual logging only here, in the NIO
            // target that already depends on swift-log. Never a hard
            // error: misalignment is sometimes intentional (e.g.
            // third-party sending infrastructure), so this only ever logs
            // a warning and always proceeds with sending.
            if let dkim = signer as? DKIMSigner, !dkim.isAligned(withFromDomain: message.from.address) {
                logger.warning(
                    "DKIM d= domain does not DMARC-align with the From: header domain",
                    metadata: ["from": "\(message.from.address)"]
                )
            }
        } else {
            finalMessage = composed
        }
        return SignedMessage(rfc5322: finalMessage.serialized())
    }
}

// MARK: - `ResultChannel`: the streaming send's actual backpressure mechanism

/// A small bounded channel bridging the sliding-window task-group producer
/// in `SMTPMailer.send<S>` to the single pull-based consumer driving
/// `AsyncThrowingStream(unfolding:)`. See that method's doc comment for the
/// full rationale -- summary: `AsyncThrowingStream.Continuation.yield` is
/// synchronous and cannot suspend, so no `bufferingPolicy` choice can make
/// it genuinely block a fast producer (confirmed empirically, not assumed --
/// it silently drops once full); this type exists to provide real
/// (suspending, non-dropping) backpressure instead, bounded to an explicit
/// `capacity`.
///
/// **Why a lock, not an actor.** This used to be an actor whose `push` and
/// `pull` registered their waiters from inside
/// `withTaskCancellationHandler { withCheckedContinuation { ... } }`
/// closures, relying on those closures inheriting the actor's isolation.
/// Under Swift 6.4, whose `withTaskCancellationHandler` and
/// `withCheckedContinuation` are `nonisolated(nonsending)`, optimized builds
/// ran `push`'s continuation body *off* the actor's executor on the second
/// pass through its wait loop. The runtime's isolation check then aborted
/// the process ("Incorrect actor executor assumption"), and when it didn't,
/// the unsynchronized waiter-list mutations lost wakeups and results. All
/// state here is behind one `NIOLockedValueBox`, so correctness no longer
/// depends on which executor any closure happens to run on, and the
/// cancellation handlers remove their waiter under the lock and resume it
/// directly instead of hopping through an unstructured `Task`.
///
/// A parked pusher hands its element over with its waiter: when `pull`
/// frees a buffer slot, it moves the oldest parked pusher's element into
/// the buffer and resumes that pusher, so a woken pusher never has to
/// re-check for room and FIFO order is preserved.
private final class ResultChannel<Element: Sendable>: Sendable {
    private struct PushWaiter {
        let id: UInt64
        let element: Element
        /// Resumed with `true` once `element` has been accepted, or `false`
        /// when it was discarded (the channel finished, or the pushing task
        /// was cancelled while parked).
        let continuation: CheckedContinuation<Bool, Never>
    }

    private struct PullWaiter {
        let id: UInt64
        let continuation: CheckedContinuation<Element?, any Error>
    }

    private struct State {
        var buffer: [Element] = []
        var isFinished = false
        var terminalError: (any Error)?
        var pushWaiters: [PushWaiter] = []
        var pullWaiter: PullWaiter?
        var nextWaiterID: UInt64 = 0

        mutating func makeWaiterID() -> UInt64 {
            nextWaiterID &+= 1
            return nextWaiterID
        }
    }

    /// What `push` does once it has released the lock.
    private enum PushAction {
        case resume(Bool)
        case handOff(CheckedContinuation<Element?, any Error>)
        case parked
    }

    /// What `pull` does once it has released the lock.
    private enum PullAction {
        case element(Element, admitted: CheckedContinuation<Bool, Never>?)
        case finished((any Error)?)
        case parked
    }

    private let capacity: Int
    private let state = NIOLockedValueBox(State())

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    /// Suspends until there is room in the buffer, the channel finishes, or
    /// this call's own `Task` is cancelled -- never drops silently and
    /// never busy-polls. Once `isFinished` (or cancellation while it would
    /// have to wait) is observed, the element is discarded rather than
    /// pushed: at that point nothing will ever `pull()` it, matching "stop
    /// promptly" rather than hanging forever trying to deliver a result
    /// nobody will read.
    func push(_ element: Element) async {
        let id = state.withLockedValue { $0.makeWaiterID() }
        _ = await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                let action: PushAction = state.withLockedValue { state in
                    if state.isFinished { return .resume(false) }
                    if let waiter = state.pullWaiter {
                        state.pullWaiter = nil
                        return .handOff(waiter.continuation)
                    }
                    if state.buffer.count < capacity {
                        state.buffer.append(element)
                        return .resume(true)
                    }
                    // Checked under the lock: the cancellation flag is set
                    // before `onCancel` runs, so either this sees it, or
                    // `onCancel` (which takes the same lock) finds this
                    // waiter registered below.
                    if Task.isCancelled { return .resume(false) }
                    state.pushWaiters.append(PushWaiter(id: id, element: element, continuation: continuation))
                    return .parked
                }
                switch action {
                case .resume(let accepted):
                    continuation.resume(returning: accepted)
                case .handOff(let puller):
                    puller.resume(returning: element)
                    continuation.resume(returning: true)
                case .parked:
                    break
                }
            }
        } onCancel: {
            let waiter: PushWaiter? = state.withLockedValue { state in
                guard let index = state.pushWaiters.firstIndex(where: { $0.id == id }) else { return nil }
                return state.pushWaiters.remove(at: index)
            }
            waiter?.continuation.resume(returning: false)
        }
    }

    /// Called by the `unfolding` closure's `produce` only --
    /// `AsyncIteratorProtocol` guarantees `next()` (and therefore
    /// `produce`) is never invoked concurrently with itself for a single
    /// iterator, so there is only ever at most one `pullWaiter` parked at
    /// a time.
    func pull() async throws -> Element? {
        let id = state.withLockedValue { $0.makeWaiterID() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Element?, any Error>) in
                let action: PullAction = state.withLockedValue { state in
                    if !state.buffer.isEmpty {
                        let element = state.buffer.removeFirst()
                        var admitted: CheckedContinuation<Bool, Never>?
                        if !state.pushWaiters.isEmpty {
                            let pusher = state.pushWaiters.removeFirst()
                            state.buffer.append(pusher.element)
                            admitted = pusher.continuation
                        }
                        return .element(element, admitted: admitted)
                    }
                    if state.isFinished { return .finished(state.terminalError) }
                    if Task.isCancelled { return .finished(CancellationError()) }
                    precondition(state.pullWaiter == nil, "ResultChannel.pull() called concurrently")
                    state.pullWaiter = PullWaiter(id: id, continuation: continuation)
                    return .parked
                }
                switch action {
                case .element(let element, let admitted):
                    admitted?.resume(returning: true)
                    continuation.resume(returning: element)
                case .finished(let error?):
                    continuation.resume(throwing: error)
                case .finished(nil):
                    continuation.resume(returning: nil)
                case .parked:
                    break
                }
            }
        } onCancel: {
            let waiter: PullWaiter? = state.withLockedValue { state in
                guard let current = state.pullWaiter, current.id == id else { return nil }
                state.pullWaiter = nil
                return current
            }
            waiter?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Marks the channel finished: no more elements will ever be accepted.
    /// Already-buffered elements are still delivered by `pull()` before it
    /// reports the end (or `error`). A parked puller (if any -- the buffer
    /// is necessarily empty then) is resolved with `error` (the source
    /// `AsyncSequence` itself threw) or `nil` (clean end of sequence); every
    /// currently-parked pusher is woken so none of them hang -- their
    /// elements are discarded (see `push`'s doc comment).
    func finish(throwing error: (any Error)?) {
        let (puller, pushers): (PullWaiter?, [PushWaiter]) = state.withLockedValue { state in
            guard !state.isFinished else { return (nil, []) }
            state.isFinished = true
            state.terminalError = error
            let puller = state.pullWaiter
            state.pullWaiter = nil
            let pushers = state.pushWaiters
            state.pushWaiters.removeAll()
            return (puller, pushers)
        }
        if let puller {
            if let error {
                puller.continuation.resume(throwing: error)
            } else {
                puller.continuation.resume(returning: nil)
            }
        }
        for pusher in pushers { pusher.continuation.resume(returning: false) }
    }
}

/// A tiny deinit-triggered cancellation hook, standing in for the
/// `onCancel`/`onTermination` parameter `AsyncThrowingStream(unfolding:)`
/// does not expose in this Swift toolchain (see `SMTPMailer.send<S>`'s doc
/// comment). An instance is captured only by the `unfolding` closure
/// itself; once that closure (and therefore this token) is released --
/// which happens when the stream/iterator is abandoned without ever being
/// exhausted -- `onDeinit` fires, exactly the "torn down without being
/// drained" signal `onTermination` would otherwise provide.
private final class StreamLifetimeToken: Sendable {
    private let onDeinit: @Sendable () -> Void
    init(onDeinit: @escaping @Sendable () -> Void) {
        self.onDeinit = onDeinit
    }
    deinit { onDeinit() }
}

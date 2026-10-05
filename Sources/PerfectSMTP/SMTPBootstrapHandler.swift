//
//  SMTPBootstrapHandler.swift
//  PerfectSMTP
//
//  Phase A of the two-phase channel lifecycle (plan §4.3): connection
//  establishment, optional implicit TLS (port 465), and — for STARTTLS —
//  the negotiate-and-upgrade dance. Kept intentionally small and low-level:
//  the STARTTLS security invariant needs byte-precise control over the
//  inbound cumulation buffer at the exact moment of upgrade, which is more
//  ergonomic with an explicit `ChannelDuplexHandler` than with an
//  already-running `NIOAsyncChannel`.
//
//  At most one outstanding reply-correlation at a time (an explicit
//  single-request state machine, never a queue) — bootstrap commands
//  (greeting wait, EHLO, STARTTLS) are never pipelined.
//
//  Once bootstrap completes, this handler removes itself from the pipeline
//  and the caller wraps the now-clean `Channel` via
//  `NIOAsyncChannel(wrappingChannelSynchronously:)` for Phase B (see
//  `SMTPConnection.swift`). Per plan §4.3 step 7, the post-bootstrap EHLO
//  (whether this is the very first EHLO, or the STARTTLS-mandated re-issue
//  with capabilities reset) is deliberately **not** sent by this handler —
//  it is Phase B's first command, issued as plain async/await code once the
//  `NIOAsyncChannel` wrapping is complete. This handler's only EHLO
//  round-trip is the narrow pre-STARTTLS one needed to discover whether the
//  server advertises STARTTLS at all, before deciding whether to attempt
//  the upgrade.
//

import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS

/// How a connection secures its transport.
public enum TLSMode: Sendable, Hashable {
    /// No TLS at all — a plaintext relay on a trusted network (plan §3's
    /// "self-hosted/internal MTA... possibly with no AUTH at all").
    case none
    /// Explicit upgrade via the `STARTTLS` command (typically port 587).
    /// Treated as mandatory once requested: if the server's pre-TLS EHLO
    /// doesn't advertise `STARTTLS`, bootstrap fails with
    /// `.starttlsRequired` rather than silently continuing in plaintext.
    case startTLS
    /// TLS from the first byte (typically port 465).
    case implicit
}

/// The async, `Sendable`-safe entry point for Phase A. Connects, performs
/// optional implicit TLS / the STARTTLS dance, and hands back a
/// pipeline-clean `NIOAsyncChannel<SMTPReply, SMTPCommand>` ready for Phase
/// B.
///
/// Two timeouts bound Phase A. `connectTimeout` covers only the TCP
/// connect. `replyTimeout` (seconds) covers each wait after that: the
/// greeting (including the implicit-TLS handshake that precedes it), the
/// pre-STARTTLS EHLO reply, the `STARTTLS` reply, and the STARTTLS
/// handshake. The clock restarts at each step, matching RFC 5321
/// §4.5.3.2's per-command timeouts (5 minutes for the greeting, hence the
/// 300-second default, which is also `SMTPConnectionPool.Configuration`'s
/// and `DirectMXConfig`'s default `replyTimeout`), so the whole bootstrap
/// is bounded by `connectTimeout` plus up to four `replyTimeout`s (with
/// STARTTLS), not by a single `replyTimeout`. When it fires, or when
/// the peer closes the connection before bootstrap completes, `connect`
/// throws and the channel is closed; without this a peer that accepted TCP
/// and then went silent, or hung up before greeting, left `connect`
/// suspended forever.
public enum SMTPBootstrap {
    public static func connect(
        host: String,
        port: Int,
        tls: TLSMode,
        connectTimeout: TimeAmount = .seconds(30),
        replyTimeout: TimeInterval = 300,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration(),
        group: any EventLoopGroup
    ) async throws -> NIOAsyncChannel<SMTPReply, SMTPCommand> {
        try await connect(
            target: .hostPort(host: host, port: port), sniHostname: host, tls: tls,
            connectTimeout: connectTimeout, replyTimeout: replyTimeout,
            tlsConfiguration: tlsConfiguration, group: group
        )
    }

    /// Connects to a pre-resolved socket address rather than letting
    /// `ClientBootstrap` perform its own hostname resolution -- for
    /// `DirectMXTransport` (plan §9 Phase 3), which has already resolved an
    /// MX exchange hostname (or, for the RFC 5321 §5.1 implicit-MX
    /// fallback, the destination domain itself) to specific A/AAAA
    /// addresses via `DNSResolver` and must connect to exactly the address
    /// it resolved -- re-resolving through the OS resolver a second time
    /// here would silently discard that work (and would also make the
    /// whole flow untestable without a real network/DNS server).
    /// `sniHostname` is still the *name* (the MX exchange, or the domain
    /// for the implicit-MX case), never the IP literal actually dialed --
    /// TLS SNI and certificate-hostname verification are about the name a
    /// certificate is expected to match, independent of which specific
    /// address that name happened to resolve to.
    public static func connect(
        to socketAddress: SocketAddress,
        sniHostname: String,
        tls: TLSMode,
        connectTimeout: TimeAmount = .seconds(30),
        replyTimeout: TimeInterval = 300,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration(),
        group: any EventLoopGroup
    ) async throws -> NIOAsyncChannel<SMTPReply, SMTPCommand> {
        try await connect(
            target: .socketAddress(socketAddress), sniHostname: sniHostname, tls: tls,
            connectTimeout: connectTimeout, replyTimeout: replyTimeout,
            tlsConfiguration: tlsConfiguration, group: group
        )
    }

    /// How the underlying `ClientBootstrap` actually dials -- the only
    /// thing that differs between the two public overloads above; the
    /// channel pipeline built below (decoder/encoder/optional implicit-TLS/
    /// `SMTPBootstrapHandler`) is identical either way.
    private enum ConnectTarget {
        case hostPort(host: String, port: Int)
        case socketAddress(SocketAddress)
    }

    private static func connect(
        target: ConnectTarget,
        sniHostname: String,
        tls: TLSMode,
        connectTimeout: TimeAmount,
        replyTimeout: TimeInterval,
        tlsConfiguration: TLSConfiguration,
        group: any EventLoopGroup
    ) async throws -> NIOAsyncChannel<SMTPReply, SMTPCommand> {
        let stepTimeout = Self.timeAmount(seconds: replyTimeout)
        let promise = group.next().makePromise(of: NIOAsyncChannel<SMTPReply, SMTPCommand>.self)

        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
            .connectTimeout(connectTimeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    // The decoder is created here (not inside the handler)
                    // so `SMTPBootstrapHandler` can hold the same reference
                    // for its STARTTLS residual-bytes check (plan §4.3 step
                    // 3) without needing any pipeline-lookup API — a plain
                    // captured class reference, resolved once at
                    // construction time.
                    let decoder = SMTPResponseDecoder()
                    try channel.pipeline.syncOperations.addHandler(
                        ByteToMessageHandler(decoder, maximumBufferSize: SMTPBootstrap.maximumReplyBufferSize),
                        name: Names.decoder
                    )
                    try channel.pipeline.syncOperations.addHandler(SMTPCommandEncoder(), name: Names.encoder)
                    if tls == .implicit {
                        let sslHandler = try Self.makeSSLHandler(host: sniHostname, configuration: tlsConfiguration)
                        try channel.pipeline.syncOperations.addHandler(sslHandler, position: .first)
                    }
                    let handler = SMTPBootstrapHandler(
                        tls: tls,
                        host: sniHostname,
                        tlsConfiguration: tlsConfiguration,
                        stepTimeout: stepTimeout,
                        readyPromise: promise,
                        initialDecoder: decoder
                    )
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }

        var connected: Channel?
        do {
            switch target {
            case .hostPort(let host, let port):
                connected = try await bootstrap.connect(host: host, port: port).get()
            case .socketAddress(let address):
                connected = try await bootstrap.connect(to: address).get()
            }
            return try await promise.futureResult.get()
        } catch {
            promise.fail(error)
            // The handler already closes the channel on every failure it
            // detects; this covers anything else, and waiting for the close
            // means the socket is gone before a caller (the pool) reuses
            // the capacity it reserved for this dial.
            if let connected {
                connected.close(promise: nil)
                try? await connected.closeFuture.get()
            }
            throw error
        }
    }

    /// `replyTimeout` as a `TimeAmount`, clamped so a huge or non-finite
    /// value means "effectively never" instead of trapping in the
    /// `Int64` conversion.
    static func timeAmount(seconds: TimeInterval) -> TimeAmount {
        guard seconds.isFinite else { return seconds > 0 ? .nanoseconds(.max) : .zero }
        let nanoseconds = max(0, seconds) * 1_000_000_000
        return nanoseconds >= Double(Int64.max) ? .nanoseconds(.max) : .nanoseconds(Int64(nanoseconds))
    }

    enum Names {
        static let decoder = "smtp-bootstrap-decoder"
        static let encoder = "smtp-command-encoder"
    }

    /// Cap on `ByteToMessageHandler`'s cumulation buffer for the SMTP reply
    /// decoder (milestone security review finding, FIX #6): NIO defaults
    /// `maximumBufferSize` to `nil` (unbounded), so a malicious/compromised
    /// server sending one arbitrarily long line with no CRLF would otherwise
    /// grow the cumulation buffer without limit -- a DoS vector that matters
    /// specifically because `TLSMode.none` (plaintext relay on a trusted
    /// network, per `RelayTransport`'s doc comment) and any relay that later
    /// turns hostile are both in scope before TLS-verification-driven trust
    /// even applies. SMTP replies are conventionally short (a handful of
    /// lines under a few hundred bytes each); 64KB is generous headroom for
    /// any real multiline EHLO/reply while being well short of unbounded.
    static let maximumReplyBufferSize = 64 * 1024

    static func makeSSLHandler(host: String, configuration: TLSConfiguration) throws -> NIOSSLClientHandler {
        let context = try NIOSSLContext(configuration: configuration)
        do {
            return try NIOSSLClientHandler(context: context, serverHostname: host)
        } catch {
            // `host` failed SNI hostname validation (e.g. it's a bare IP
            // address, which NIOSSL's SNI validator rejects outright per
            // RFC 6066 §3) -- fall back to no SNI. This is NOT a
            // verification bypass: `serverHostname: nil` only disables the
            // SNI *extension* sent during the handshake (a hint some
            // servers use for virtual hosting); it does not disable
            // certificate verification. NIOSSL still performs full
            // certificate-chain validation and still checks the peer's
            // certificate against the real connection address -- for an
            // IP-literal host specifically, that means verifying an
            // iPAddress `subjectAltName` entry (RFC 6125 §6.4.2/RFC 5280)
            // against the actual peer IP, exactly the check that would
            // otherwise catch a MITM presenting the wrong certificate.
            // Confirmed safe by the security review.
            return try NIOSSLClientHandler(context: context, serverHostname: nil)
        }
    }
}

/// Phase A's explicit state machine. `@unchecked Sendable`: constructed on,
/// and every callback dispatched on, its channel's single event loop —
/// never touched concurrently, matching this codebase's other
/// event-loop-confined handler precedents (e.g. PerfectNIO's
/// `WebSocketUpgradeRouter`).
final class SMTPBootstrapHandler: ChannelDuplexHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = SMTPReply
    typealias OutboundIn = Never
    typealias OutboundOut = SMTPCommand

    private enum State: Equatable {
        case awaitingGreeting
        case awaitingPreTLSEHLOReply
        case awaitingStartTLSReply
        /// Between "decided to upgrade" and "TLS handshake confirmed
        /// complete". Any inbound reply or error surfacing here — other
        /// than the TLS handshake-completed user event itself — is treated
        /// as `.starttlsInjection`: nothing else should legitimately
        /// produce channel activity in this fenced window.
        case upgrading
        case finished
        case failed
    }

    private let tls: TLSMode
    private let host: String
    private let tlsConfiguration: TLSConfiguration
    /// How long each bootstrap step (greeting, pre-TLS EHLO reply,
    /// STARTTLS reply, STARTTLS handshake) may take; see `SMTPBootstrap`.
    private let stepTimeout: TimeAmount
    private var stepTimer: Scheduled<Void>?
    private let readyPromise: EventLoopPromise<NIOAsyncChannel<SMTPReply, SMTPCommand>>
    /// The pre-upgrade decoder — same reference `ByteToMessageHandler` was
    /// constructed with in the channel initializer. Queried, never
    /// swapped: the post-upgrade decoder is Phase B's concern, not this
    /// handler's.
    private let initialDecoder: SMTPResponseDecoder

    private var state: State = .awaitingGreeting

    init(
        tls: TLSMode,
        host: String,
        tlsConfiguration: TLSConfiguration,
        stepTimeout: TimeAmount = .seconds(300),
        readyPromise: EventLoopPromise<NIOAsyncChannel<SMTPReply, SMTPCommand>>,
        initialDecoder: SMTPResponseDecoder
    ) {
        self.tls = tls
        self.host = host
        self.tlsConfiguration = tlsConfiguration
        self.stepTimeout = stepTimeout
        self.readyPromise = readyPromise
        self.initialDecoder = initialDecoder
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // `SMTPBootstrap` adds this handler before connecting, so the
        // greeting clock normally starts in `channelActive`; this covers a
        // handler added to an already-connected channel.
        if context.channel.isActive {
            armStepTimer(context: context)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        // TCP is up (`connectTimeout` no longer applies): start the clock
        // on the greeting.
        armStepTimer(context: context)
        context.fireChannelActive()
    }

    /// The peer hung up (or the connection otherwise dropped) before
    /// bootstrap finished. Nothing else would complete `readyPromise` in
    /// that case. Before the upgrade this is an ordinary connection
    /// failure; inside the fenced `.upgrading` window it is reported the
    /// same way as every other failure there (see `errorCaught`), so it
    /// never becomes a plaintext-fallback trigger for opportunistic TLS.
    /// In practice a close mid-handshake usually reaches `errorCaught`
    /// first, as NIOSSL's `.handshakeFailed(eofDuringHandshake)`.
    func channelInactive(context: ChannelHandlerContext) {
        switch state {
        case .awaitingGreeting, .awaitingPreTLSEHLOReply, .awaitingStartTLSReply:
            fail(context: context, .connectionFailed(SMTPConnectionError.channelClosedByPeer))
        case .upgrading:
            fail(context: context, .starttlsInjection(underlying: SMTPConnectionError.channelClosedByPeer))
        case .finished, .failed:
            break
        }
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        cancelStepTimer()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let reply = Self.unwrapInboundIn(data)
        switch state {
        case .awaitingGreeting:
            handleGreeting(reply, context: context)
        case .awaitingPreTLSEHLOReply:
            handlePreTLSEHLOReply(reply, context: context)
        case .awaitingStartTLSReply:
            handleStartTLSReply(reply, context: context)
        case .upgrading, .finished, .failed:
            // Unsolicited reply: no promise/state was waiting for this.
            // During `.upgrading` specifically this is exactly the
            // CVE-2026-41319-class injection this handler exists to catch.
            // In `.finished`/`.failed` it's simply a stray event on a
            // handler that should already be gone/inert; fail closed.
            // No underlying error exists here -- this is a plain logic
            // check ("a reply arrived when none should have"), not
            // something surfaced via `errorCaught`.
            fail(context: context, .starttlsInjection(underlying: nil))
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let tlsEvent = event as? TLSUserEvent, case .handshakeCompleted = tlsEvent {
            guard state == .upgrading else {
                // A handshake-completed event outside the upgrade window
                // (e.g. implicit TLS, where we never entered `.upgrading`
                // at all) is expected and ignored -- the greeting/EHLO flow
                // handles readiness in that mode.
                context.fireUserInboundEventTriggered(event)
                return
            }
            // `autoRead` was already re-enabled in `insertTLSAndFreshDecoder`
            // (see that method's comment) -- nothing left to toggle here,
            // just hand off to Phase B.
            finish(context: context)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard state == .upgrading else {
            fail(context: context, .connectionFailed(error))
            return
        }
        // Any error surfacing in the fenced upgrade window -- whether the
        // decoder's own `residualBytesOnRemoval` (same-buffer injection,
        // surfaced here via `context.fireErrorCaught` since
        // `ByteToMessageHandler` routes decode-time errors through
        // `errorCaught` rather than through `removeHandler`'s own promise)
        // or NIOSSL failing to parse injected plaintext as a TLS record
        // (separate-buffer injection) -- is the same underlying violation.
        // Milestone review finding: distinguish the two so a genuine TLS
        // handshake failure (expired cert, cipher mismatch, network reset)
        // isn't indistinguishable from an actual injection attempt in
        // logs/metrics. The same-buffer path's `DecoderError` carries no
        // diagnostic value beyond the residual-bytes fact `.starttlsInjection`
        // itself already captures -- pass `nil`. Every other error reaching
        // here (a real NIOSSL/handshake failure, a connection-level error)
        // has genuine diagnostic value -- pass it through.
        let underlying: (any Error & Sendable)? = error is SMTPResponseDecoder.DecoderError ? nil : error
        fail(context: context, .starttlsInjection(underlying: underlying))
    }

    // MARK: - State transitions

    private func handleGreeting(_ reply: SMTPReply, context: ChannelHandlerContext) {
        // RFC 5321 §3.1 requires exactly `220` for the initial greeting --
        // not any `2yz`. Matches the stricter `reply.code == 220` check
        // already used for the STARTTLS reply itself in
        // `handleStartTLSReply`.
        guard reply.code == 220 else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        switch tls {
        case .none, .implicit:
            finish(context: context)
        case .startTLS:
            state = .awaitingPreTLSEHLOReply
            armStepTimer(context: context)
            writeLine(context: context, "EHLO \(Self.probeHostname)")
        }
    }

    private func handlePreTLSEHLOReply(_ reply: SMTPReply, context: ChannelHandlerContext) {
        guard reply.replyClass == .positiveCompletion else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        let capabilities = Capabilities(parsingEHLOLines: reply.lines)
        guard capabilities.startTLS else {
            fail(context: context, .starttlsRequired)
            return
        }
        state = .awaitingStartTLSReply
        armStepTimer(context: context)
        writeLine(context: context, "STARTTLS")
        // NOTE: `autoRead = false` is deliberately NOT set here. Setting it
        // at this point -- before the server's `220` has even arrived --
        // synchronously deregisters the socket's read interest at the
        // kqueue/epoll level on this `true -> false` transition (verified
        // against the resolved NIOPosix source). Once that happens, the
        // reactor is never notified when the `220` bytes physically arrive:
        // they sit unread in the kernel socket buffer forever, and this
        // handler hangs waiting for a reply it will never be woken for.
        // This was invisible against `EmbeddedChannel` (used by
        // `STARTTLSTests`), which hardcodes `autoRead` as always-effectively-
        // on and never models real read-interest deregistration -- see the
        // blind-spot comment on `STARTTLSTests` itself. The fence now
        // happens at the start of `handleStartTLSReply`, synchronously in
        // reaction to the `220`, which still closes the same TOCTOU gap:
        // see that method's doc comment for why.
    }

    private func handleStartTLSReply(_ reply: SMTPReply, context: ChannelHandlerContext) {
        guard reply.code == 220 else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        // Step 2 (moved here from `handlePreTLSEHLOReply`, see that
        // method's comment for why): fence `autoRead` off as the very
        // first action taken in response to receiving and validating the
        // `220`, before the residual-bytes check and before the async
        // decoder-removal -- still within the same reactor turn/
        // `channelRead` call stack that delivered the `220`.
        //
        // This still closes the same TOCTOU gap the plan's §4.3 step 2
        // describes: `ByteToMessageHandler` drains all currently-cumulated
        // bytes for one kernel `read()` synchronously, in a single
        // `channelRead` dispatch, before yielding back to the event loop --
        // so same-buffer-injected bytes (arriving concatenated into the
        // same TCP segment as the `220`) are still sitting in the decoder's
        // buffer right now and are still caught by the residual-bytes check
        // below regardless of exactly where within this synchronous stretch
        // `autoRead` gets disabled. What disabling it here *does* correctly
        // prevent is a *separate*, subsequent kernel `read()` (a
        // separate-buffer injection, e.g. a second TCP segment) from being
        // serviced -- and its bytes handed to `errorCaught`/`channelRead`
        // on this handler -- before the plaintext decoder is swapped out
        // for the post-TLS one. That is the actual invariant the plan cares
        // about, and disabling `autoRead` synchronously here (rather than
        // earlier, before the `220` even arrived) achieves it without ever
        // deregistering read interest before the reply we're blocking on
        // has been delivered.
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.autoRead, value: false).whenFailure { [weak self] error in
            self?.fail(context: boundContext.value, .connectionFailed(error))
        }
        // Step 3: residual-bytes assertion on the buffer that produced this
        // 220 -- catches bytes injected into the *same* read as the 220.
        // No underlying error here either -- a direct boolean check, not
        // something caught via `errorCaught`.
        guard !initialDecoder.hasResidualBytesAfterLastReply else {
            fail(context: context, .starttlsInjection(underlying: nil))
            return
        }
        performTLSUpgrade(context: context)
    }

    private func performTLSUpgrade(context: ChannelHandlerContext) {
        state = .upgrading
        // The handshake gets its own full step.
        armStepTimer(context: context)
        // Step 4: remove the plaintext decoder. Its `decodeLast` override
        // re-validates no residual bytes remain and throws
        // `.residualBytesOnRemoval` otherwise, surfacing via `errorCaught`
        // above -- defense-in-depth alongside the check just performed.
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.pipeline.removeHandler(name: SMTPBootstrap.Names.decoder).whenComplete { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.fail(context: boundContext.value, .connectionFailed(error))
            case .success:
                self.insertTLSAndFreshDecoder(context: boundContext.value)
            }
        }
    }

    private func insertTLSAndFreshDecoder(context: ChannelHandlerContext) {
        guard state == .upgrading else { return }
        do {
            // Step 5: NIOSSLClientHandler at `.first`.
            let sslHandler = try SMTPBootstrap.makeSSLHandler(host: host, configuration: tlsConfiguration)
            try context.pipeline.syncOperations.addHandler(sslHandler, position: .first)
            // Step 6: a fresh decoder above it.
            try context.pipeline.syncOperations.addHandler(
                ByteToMessageHandler(SMTPResponseDecoder(), maximumBufferSize: SMTPBootstrap.maximumReplyBufferSize),
                name: SMTPBootstrap.Names.decoder,
                position: .after(sslHandler)
            )
            // Re-enable `autoRead` here, immediately -- matching the plan's
            // literal step 6 ("add a fresh decoder, then re-enable
            // autoRead"), NOT deferred until the handshake-completed event
            // (a second real-socket hang found via this fix pass's own
            // real-socket regression test, `STARTTLSRealSocketTests`):
            // `NIOSSLClientHandler` writes its `ClientHello` on `handlerAdded`
            // (an outbound action, needing no read interest), but receiving
            // the server's handshake response requires read interest to
            // already be registered -- `NIOSSLHandler`'s own internal
            // `context.read()` pull (in `doFlushReadData`) only fires
            // *after* a `channelRead` has already occurred, so if read
            // interest is still deregistered at this point, no
            // `channelRead` ever happens, `context.read()` is never called,
            // and the handshake can never receive its first byte -- a
            // deadlock on any real socket, invisible against
            // `EmbeddedChannel` (see `STARTTLSTests`' blind-spot comment)
            // for the same reason as the original FIX #1 bug.
            //
            // Re-enabling here does NOT reopen the injection window: the
            // security invariant was never actually "autoRead stays off
            // until handshake-complete" -- it comes from `NIOSSLClientHandler`
            // now sitting *ahead of* (upstream of, in inbound order) both
            // the fresh decoder and this handler. Any bytes that arrive
            // now, injected or legitimate, are first fed through
            // `sslHandler`, which either (a) successfully continues the
            // real TLS handshake, or (b) fails to parse them as a valid TLS
            // record / fails certificate verification, surfacing as
            // `errorCaught` -- mapped to `.starttlsInjection` below exactly
            // as before. There is no path from raw injected plaintext to
            // this handler's `channelRead` (the fresh decoder, and this
            // handler behind it, only ever see `sslHandler`'s decrypted
            // output) regardless of `autoRead`'s state.
            let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
            context.channel.setOption(ChannelOptions.autoRead, value: true).whenFailure { [weak self] error in
                self?.fail(context: boundContext.value, .connectionFailed(error))
            }
        } catch {
            fail(context: context, .connectionFailed(error))
        }
    }

    private func finish(context: ChannelHandlerContext) {
        guard state != .finished, state != .failed else { return }
        state = .finished
        cancelStepTimer()
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.pipeline.syncOperations.removeHandler(context: context).whenComplete { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.readyPromise.fail(error)
            case .success:
                do {
                    let asyncChannel = try NIOAsyncChannel<SMTPReply, SMTPCommand>(
                        wrappingChannelSynchronously: boundContext.value.channel
                    )
                    self.readyPromise.succeed(asyncChannel)
                } catch {
                    self.readyPromise.fail(error)
                }
            }
        }
    }

    private func fail(context: ChannelHandlerContext, _ error: SMTPError) {
        guard state != .finished, state != .failed else { return }
        state = .failed
        cancelStepTimer()
        context.close(promise: nil)
        readyPromise.fail(error)
    }

    /// (Re)starts the per-step clock. On expiry the bootstrap fails with
    /// `SMTPConnectionError.replyTimedOut`, wrapped the same way
    /// `channelInactive` wraps a hang-up, and `fail` closes the channel.
    private func armStepTimer(context: ChannelHandlerContext) {
        cancelStepTimer()
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        stepTimer = context.eventLoop.scheduleTask(in: stepTimeout) { [weak self] in
            guard let self else { return }
            let error: SMTPError = self.state == .upgrading
                ? .starttlsInjection(underlying: SMTPConnectionError.replyTimedOut)
                : .connectionFailed(SMTPConnectionError.replyTimedOut)
            self.fail(context: boundContext.value, error)
        }
    }

    private func cancelStepTimer() {
        stepTimer?.cancel()
        stepTimer = nil
    }

    private func writeLine(context: ChannelHandlerContext, _ line: String) {
        context.writeAndFlush(Self.wrapOutboundOut(.line(line)), promise: nil)
    }

    /// The EHLO identity used for the narrow pre-STARTTLS capability probe
    /// only. Phase B's real EHLO (issued post-bootstrap) uses the caller's
    /// actual configured EHLO hostname (plan §7's "no configurable
    /// EHLO/HELO hostname" gap) -- this probe's own identity doesn't matter
    /// since its only purpose is discovering whether STARTTLS is
    /// advertised, and its capabilities are discarded, never reused past
    /// the upgrade.
    private static let probeHostname = "localhost"
}

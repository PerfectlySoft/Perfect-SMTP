//
//  DirectMXTransport.swift
//  PerfectSMTP
//
//  Plan §3/§4.2/§9 Phase 3: Perfect-SMTP being its own terminal MTA --
//  direct-to-recipient delivery via MX resolution, no relay. Builds
//  directly on the Phase-3a `DNSResolver` (via the `MXResolving` seam) and
//  reuses `SMTPConnectionPool` as-is (not a second pool *type* -- see the
//  file-level note on `makeDialer` below for why its existing
//  `Key { host, port, tls }` shape and `withConnection(to:_:)` API already
//  fit a multi-destination direct-MX pool with no relay-specific
//  assumptions to work around), keyed here by resolved MX exchange
//  hostname (or, for the implicit-MX fallback, the destination domain
//  itself) instead of one fixed relay host.
//

import Foundation
import Logging
import NIOCore

/// The TLS policy `DirectMXTransport` applies when dialing a resolved MX
/// host (plan §9 Phase 4). `DirectMXTransport` itself layers per-domain
/// MTA-STS policy (RFC 8461 `testing`/`enforce`) on top of whichever of
/// these two a `DirectMXConfig` is configured with -- see that type's own
/// doc comments for exactly how `enforce`/`testing` interact with each
/// case here.
public enum DirectMXTLSPolicy: Sendable, Equatable {
    /// Phase 3's exact original behavior, preserved as an explicit escape
    /// hatch: every connection attempt against every resolved host uses
    /// exactly this `TLSMode`, uniformly, with **no** opportunistic
    /// fallback and **no** MTA-STS involvement at all -- even a domain
    /// that publishes an `enforce` MTA-STS policy is delivered to exactly
    /// as configured here, never restricted to policy-matching hosts. For
    /// a caller who wants full manual control (e.g. mandatory STARTTLS
    /// against every destination, explicitly accepting that domains
    /// without STARTTLS become undeliverable-by-this-transport -- Phase
    /// 3's own documented recipe for that) or who has their own reasons to
    /// opt out of Phase 4's new default entirely.
    case fixed(TLSMode)
    /// **Phase 4's new default** (plan §9 Phase 4, point 4 -- closes the
    /// gap Phase 3 explicitly deferred: "opportunistic TLS is Phase
    /// 4/MTA-STS scope"). Per resolved MX host: try `TLSMode.startTLS`
    /// first (mandatory-verified, real certificate/hostname checking, same
    /// as `.startTLS` always does in this codebase); if the server's EHLO
    /// doesn't advertise STARTTLS at all (bootstrap throws
    /// `.starttlsRequired`), retry the *same host* with `TLSMode.none`
    /// instead of treating that host as unreachable.
    ///
    /// FIX #5 (milestone review, doc-accuracy): **the plaintext-fallback
    /// path described above is essentially unreachable for a handshake/
    /// certificate failure specifically -- do not read this case as "a
    /// genuine cert failure falls back to plaintext."** `SMTPBootstrapHandler
    /// .errorCaught` (Phase 1, unchanged, existing fail-safe fencing)
    /// classifies **every** error surfacing during the STARTTLS upgrade
    /// window -- a real NIOSSL/certificate-verification failure exactly as
    /// much as actual injected bytes -- as `SMTPError.starttlsInjection`.
    /// That is intentional, correct fail-safe behavior (an attacker's
    /// injected bytes and a merely-misconfigured certificate are
    /// deliberately indistinguishable at that layer, so both are treated
    /// as the more dangerous possibility), but it means this case's
    /// plaintext retry in practice only ever fires when STARTTLS is
    /// genuinely **not offered at all** by the peer. A domain whose sole MX
    /// host advertises STARTTLS but presents a merely-misconfigured
    /// (non-malicious) certificate will hard-fail that host under
    /// `.opportunistic` rather than falling back to plaintext -- this is
    /// the correct, reviewed behavior, not a bug, but is called out
    /// explicitly here because an earlier version of this doc comment
    /// described the unreachable-in-practice "genuine cert failure ->
    /// plaintext retry" path as if it were the common case.
    ///
    /// **Never** falls back to plaintext after a detected
    /// `SMTPError.starttlsInjection` -- see
    /// `DirectMXTransport.deliverToDomain`'s opportunistic-attempt helper
    /// for exactly where that distinction is enforced; an injection
    /// detection on one host simply moves on to the next resolved MX host
    /// (ordinary host-level fallback), never retries that same host
    /// unauthenticated. The same helper also never retries a host in
    /// plaintext after `SMTPError.circuitOpen` (FIX #1, milestone security
    /// review) -- see `mustNeverTriggerAPlaintextRetryAgainstThisHost`'s
    /// doc comment for why an ambiguous circuit-breaker signal gets the
    /// same treatment as a confirmed injection detection.
    ///
    /// When a domain publishes an MTA-STS `testing` or `enforce` policy
    /// (and a `mtaSTSPolicyProvider` is configured), that policy's stronger
    /// requirements apply on top of -- and, for `enforce`'s mandatory-TLS-
    /// only/host-restriction rules, in place of -- this opportunistic
    /// default for that specific domain; a domain with no policy (or an
    /// explicit `mode: none` policy) gets exactly the behavior described
    /// here.
    case opportunistic
}

/// Configuration for one `DirectMXTransport` instance. Applies uniformly to
/// every destination this transport connects to, modulated per-domain only
/// by MTA-STS policy when a `mtaSTSPolicyProvider` is configured on
/// `DirectMXTransport` (plan §9 Phase 4) -- there is no other per-domain
/// override surface.
///
/// **Security (FIX #2, milestone security review): this transport must not
/// be exposed to untrusted recipient input without SSRF-class address
/// filtering enabled** -- `allowPrivateAddresses` defaults to `false`
/// (filtering on) specifically because `DirectMXTransport` resolves and
/// dials whatever MX/A/AAAA records a destination domain publishes. A
/// caller that lets an untrusted party influence the recipient domain (a
/// web app's "share via email" feature, a future Lasso `email_send`
/// adapter, etc.) would otherwise let an attacker publish a record
/// pointing at `127.0.0.1`, an RFC 1918 address, or other internal
/// infrastructure and have this transport open a real TCP connection and
/// run a full SMTP conversation against it. Leave `allowPrivateAddresses`
/// at its default unless the caller's own equivalent protection is already
/// in place, or this is a deliberate internal-relay-testing use case.
public struct DirectMXConfig: Sendable {
    /// The port dialed on every resolved MX host. 25 (not 587/465) is
    /// correct here: this transport speaks MTA-to-MTA delivery, the
    /// universal port every receiving MX host listens on, not
    /// client-submission.
    public var port: Int
    /// TLS policy applied to every direct-MX destination this transport
    /// connects to. **Phase 4 (plan §9) changes the default from Phase 3's
    /// fixed `.none` to `.opportunistic`** -- see `DirectMXTLSPolicy
    /// .opportunistic`'s doc comment for exactly what that means and why;
    /// in short, this transport now *tries* STARTTLS by default wherever a
    /// server advertises it, instead of never even attempting TLS unless a
    /// caller explicitly configured it (Phase 3's own documented gap, left
    /// open specifically for this phase to close -- see that phase's git
    /// history / this property's prior doc comment, preserved in
    /// `DirectMXTLSPolicy.fixed`'s doc comment for the caller who still
    /// wants that exact Phase 3 behavior). MTA-STS policy (when a
    /// `mtaSTSPolicyProvider` is configured on `DirectMXTransport`) can
    /// upgrade `.opportunistic`'s per-domain behavior to `testing`/
    /// `enforce` semantics on top of this default -- see
    /// `DirectMXTransport`'s own doc comments for exactly how.
    public var tlsPolicy: DirectMXTLSPolicy
    public var ehloHostname: String
    /// **Direct-MX-specific note (not a Phase-1 concern):** `RelayTransport`
    /// owns one pool per configured relay, so `maxTotal` is naturally a cap
    /// on connections to that single destination. `DirectMXTransport`
    /// shares **one** pool instance across every distinct destination
    /// domain/MX host in a batch (see this type's own doc comment), so
    /// `maxTotal` here is a hard global cap across *all* domains combined,
    /// not per-domain -- a caller doing meaningful batch volume across many
    /// domains should likely raise it above the Phase-1 default (32).
    public var pool: SMTPConnectionPool.Configuration
    public var connectTimeout: TimeAmount
    /// Per-reply timeout for every SMTP step, including each step of the
    /// dial's bootstrap (greeting, STARTTLS exchange and handshake; see
    /// `SMTPBootstrap`).
    public var replyTimeout: TimeInterval
    public var dataTerminationTimeout: TimeInterval
    /// FIX #2 (milestone security review): SSRF-class filtering is
    /// default-**on** -- every resolved `DNSAddress` is checked against
    /// `DNSAddress.isRoutable` (private/loopback/link-local/unique-local/
    /// CGNAT ranges, see that property's doc comment) before this
    /// transport ever dials it, and an address that fails the check is
    /// dropped rather than connected to. Set `true` only for a deliberate
    /// internal-relay-testing use case (e.g. a test harness or an
    /// intentionally internal-only deployment) -- see this type's own doc
    /// comment for the attack this default protects against.
    public var allowPrivateAddresses: Bool

    public init(
        port: Int = 25,
        tlsPolicy: DirectMXTLSPolicy = .opportunistic,
        ehloHostname: String = "localhost",
        pool: SMTPConnectionPool.Configuration = .init(),
        connectTimeout: TimeAmount = .seconds(30),
        replyTimeout: TimeInterval = 300,
        dataTerminationTimeout: TimeInterval = 600,
        allowPrivateAddresses: Bool = false
    ) {
        self.port = port
        self.tlsPolicy = tlsPolicy
        self.ehloHostname = ehloHostname
        self.pool = pool
        self.connectTimeout = connectTimeout
        self.replyTimeout = replyTimeout
        self.dataTerminationTimeout = dataTerminationTimeout
        self.allowPrivateAddresses = allowPrivateAddresses
    }
}

/// Errors specific to MX-resolution/host-fallback bookkeeping (as opposed
/// to `SMTPError`, which classifies SMTP-level replies, or
/// `DirectMXRetryQueueError`, which classifies retry-queue bookkeeping
/// failures).
public enum DirectMXError: Error, Sendable, Equatable {
    /// Every MX host resolved for a domain (or, for the implicit-MX
    /// fallback, the domain itself) failed to connect. Carried alongside
    /// the last host's actual underlying error in the common path (see
    /// `DirectMXTransport.deliverToDomain`) -- this case is the fallback
    /// used only when there were no candidate hosts to even try.
    case noUsableMXHost(domain: String)
    /// A candidate host resolved to no usable A/AAAA address at all.
    case noUsableAddress(host: String)
    /// FIX #2 (milestone security review): every A/AAAA address resolved
    /// for `host` was filtered out as private/loopback/link-local/
    /// unique-local/CGNAT (see `DNSAddress.isRoutable`) -- distinct from
    /// `.noUsableAddress` (which means the resolver returned nothing at
    /// all) specifically so this is diagnosable as "this host published an
    /// address this transport refuses to dial" rather than a mysterious
    /// connection failure indistinguishable from a genuine DNS/network
    /// problem. Never thrown when `DirectMXConfig.allowPrivateAddresses`
    /// is `true`.
    case allResolvedAddressesFilteredAsPrivate(host: String)
}

/// A `SMTPTransport` that resolves MX records itself and delivers directly
/// to the destination's own mail exchanger(s) -- no relay in front. Per-
/// recipient delivery: `envelope.recipients` is grouped by destination
/// domain (MX resolution and connection pooling both happen at the domain
/// level), each domain's MX hosts are resolved and attempted independently,
/// and one `DeliveryResult` is produced per recipient reflecting that
/// recipient's own domain's outcome -- a failure delivering to one
/// recipient's domain never affects delivery to a different recipient's
/// domain in the same call (enforced by running each domain's delivery as
/// its own child task and never letting one child's outcome influence
/// another's).
public final class DirectMXTransport: SMTPTransport, Sendable {
    private let resolver: any MXResolving
    private let pool: SMTPConnectionPool
    private let config: DirectMXConfig
    private let retryQueueConfiguration: DirectMXRetryQueue.Configuration
    private let retryQueue: DirectMXRetryQueue
    /// `nil` (the default) means MTA-STS is not consulted at all for any
    /// domain -- every destination gets exactly `config.tlsPolicy`'s
    /// behavior (plan §9 Phase 4's opportunistic-by-default, unless
    /// overridden to `.fixed`), with no per-domain policy lookup, no DNS
    /// TXT query, and no HTTPS fetch ever attempted. This is a deliberate,
    /// purely-additive default: a caller who doesn't pass this parameter
    /// gets no new network dependency and no behavior change beyond the
    /// opportunistic-TLS default itself (see `DirectMXTLSPolicy
    /// .opportunistic`'s doc comment) -- MTA-STS enforcement is opt-in by
    /// supplying a `MTASTSPolicyManager` (or a test fake conforming to
    /// `MTASTSPolicyProviding`) here.
    private let mtaSTSPolicyProvider: (any MTASTSPolicyProviding)?
    private let logger: Logger

    /// - Parameters:
    ///   - resolver: Anything conforming to `MXResolving` -- a real
    ///     `DNSResolver` in production, a fake in tests (see
    ///     `MXResolving.swift`'s doc comment for why this seam exists).
    ///   - config: Applies uniformly to every destination -- see
    ///     `DirectMXConfig`'s doc comments, especially `tlsPolicy`'s
    ///     default.
    ///   - group: The `EventLoopGroup` both the connection pool and every
    ///     dialed connection run on.
    ///   - retryQueueConfiguration: Backoff durations and the retry
    ///     ceiling/expiry policy for this transport's owned
    ///     `DirectMXRetryQueue` -- see that type's `Configuration` doc
    ///     comments.
    ///   - mtaSTSPolicyProvider: `nil` (the default) disables MTA-STS
    ///     entirely for this transport instance -- see this type's own
    ///     stored-property doc comment. Pass a `MTASTSPolicyManager` to
    ///     opt in.
    ///   - logger: Used only to record MTA-STS `testing`-mode discrepancies
    ///     (a policy-matched host failed mandatory TLS and delivery fell
    ///     back to unconstrained opportunistic delivery -- RFC 8460 TLSRPT
    ///     aggregate reporting is explicitly out of scope, plan §9 Phase 4;
    ///     this is the "make sure testing-mode failures are distinguishable
    ///     in whatever result/logging surface makes sense" substitute) and
    ///     `enforce`-mode hard-fails, matching `SMTPMailer`'s own narrow,
    ///     documented use of a logger for its DMARC-alignment lint.
    ///   - onTerminalRetryOutcome: Forwarded to the owned
    ///     `DirectMXRetryQueue` -- see that type's `init` doc comment for
    ///     why this is the only way a caller observes a *background*
    ///     retry's final outcome.
    public convenience init(
        resolver: any MXResolving,
        config: DirectMXConfig = .init(),
        group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration = .init(),
        mtaSTSPolicyProvider: (any MTASTSPolicyProviding)? = nil,
        logger: Logger = Logger(label: "PerfectSMTP.DirectMXTransport"),
        onTerminalRetryOutcome: (@Sendable (DeliveryResult) async -> Void)? = nil
    ) {
        self.init(
            resolver: resolver, config: config, group: group,
            retryQueueConfiguration: retryQueueConfiguration, mtaSTSPolicyProvider: mtaSTSPolicyProvider,
            logger: logger, onTerminalRetryOutcome: onTerminalRetryOutcome,
            dialer: Self.makeDialer(resolver: resolver, config: config, group: group, retryQueueConfiguration: retryQueueConfiguration)
        )
    }

    /// Test/internal-only initializer: overrides the pool's dialer entirely
    /// (bypassing real DNS-driven address resolution and real socket
    /// connects), matching `SMTPConnectionPool`'s own test-dialer seam
    /// (`SMTPConnectionPoolTests`) -- lets MX-host-fallback / circuit-
    /// breaker tests script exactly which pool `Key` (i.e. which MX host)
    /// succeeds or fails, using `ConnectionHarness`-backed in-memory
    /// connections for the ones that should succeed.
    init(
        resolver: any MXResolving,
        config: DirectMXConfig = .init(),
        group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration = .init(),
        mtaSTSPolicyProvider: (any MTASTSPolicyProviding)? = nil,
        logger: Logger = Logger(label: "PerfectSMTP.DirectMXTransport"),
        onTerminalRetryOutcome: (@Sendable (DeliveryResult) async -> Void)? = nil,
        dialer: @escaping @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection
    ) {
        self.resolver = resolver
        self.config = config
        self.retryQueueConfiguration = retryQueueConfiguration
        self.mtaSTSPolicyProvider = mtaSTSPolicyProvider
        self.logger = logger
        let pool = SMTPConnectionPool(configuration: config.pool, group: group, dialer: dialer)
        self.pool = pool
        // Deliberately built from local `let`s (`resolver`/`config`/`pool`/
        // `retryQueueConfiguration`/`mtaSTSPolicyProvider`/`logger`), never
        // from `self.<property>` -- this closure is constructed before
        // every one of `self`'s stored properties is set, and capturing
        // `self` itself here (even weakly) would need those properties
        // already initialized. Using the local values `performDelivery`
        // needs sidesteps the ordering question entirely: `performDelivery`
        // is a `static` function that takes everything explicitly, so
        // nothing here ever touches `self`.
        self.retryQueue = DirectMXRetryQueue(
            configuration: retryQueueConfiguration,
            redeliver: { envelope, message in
                await Self.performDelivery(
                    envelope: envelope, message: message, resolver: resolver, pool: pool,
                    config: config, retryQueueConfiguration: retryQueueConfiguration,
                    mtaSTSPolicyProvider: mtaSTSPolicyProvider, logger: logger
                )
            },
            onTerminalOutcome: onTerminalRetryOutcome
        )
    }

    /// Resolves and delivers directly to `envelope.recipients`' own MX
    /// hosts, per-domain (see `deliverToDomain`'s doc comment for the full
    /// host-fallback/TLS-policy/MTA-STS decision tree). Unlike
    /// `RelayTransport`/`LocalMTATransport`, a `.queuedForRetry` result from
    /// this call is automatically enqueued onto this transport's own
    /// `DirectMXRetryQueue` and redelivered in the background (see
    /// `enqueueRetries(from:mailFrom:message:)`) -- callers don't need to
    /// re-invoke `send` themselves to get retry behavior. This method
    /// itself never throws; every failure mode (DNS, connection, SMTP-level
    /// rejection) is represented as a per-recipient `DeliveryResult`.
    public func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        let results = await Self.performDelivery(
            envelope: envelope, message: message, resolver: resolver, pool: pool,
            config: config, retryQueueConfiguration: retryQueueConfiguration,
            mtaSTSPolicyProvider: mtaSTSPolicyProvider, logger: logger
        )
        await enqueueRetries(from: results, mailFrom: envelope.mailFrom, message: message)
        return results
    }

    /// Stops this transport's background retry queue (abandoning any
    /// still-pending scheduled redeliveries -- see `pendingRetryEntries()`
    /// to inspect what those are before calling this) and closes every
    /// pooled connection to every destination host this transport has
    /// dialed. Does not close the `EventLoopGroup` this transport was
    /// constructed with.
    public func shutdown() async {
        await retryQueue.shutdown()
        await pool.shutdown()
    }

    /// Exposed for callers/tests that want visibility into what this
    /// transport's owned retry queue is still holding, without wiring up
    /// `onTerminalRetryOutcome`.
    public func pendingRetryEntries() async -> [DirectMXRetryQueue.Entry] {
        await retryQueue.pendingEntriesSnapshot()
    }

    /// One retry-queue entry per recipient that came back `.queuedForRetry`
    /// from this call -- see `DirectMXRetryQueue.Entry.recipients`'s doc
    /// comment for why per-recipient (not batched-by-transaction) is the
    /// deliberate granularity. `.ambiguous` results are never passed
    /// through to `DirectMXRetryQueue.enqueue` as anything other than a
    /// guaranteed no-op (that guard lives on the queue itself, per that
    /// type's doc comment) -- this loop doesn't need its own `.ambiguous`
    /// check to uphold that invariant, but the `guard case .queuedForRetry`
    /// below means it never even reaches the queue's own guard for any
    /// other outcome either.
    private func enqueueRetries(from results: [DeliveryResult], mailFrom: ReversePath, message: SignedMessage) async {
        for result in results {
            guard case .queuedForRetry = result.outcome else { continue }
            await retryQueue.enqueue(recipients: [result.recipient], mailFrom: mailFrom, message: message, outcome: result.outcome)
        }
    }

    // MARK: - Delivery (static: no `self` capture needed, callable from `init`'s `redeliver` closure and from `send`)

    /// Groups `envelope.recipients` by destination domain and attempts
    /// each domain's delivery independently and concurrently (one child
    /// task per domain) -- a failure for one domain can never affect
    /// another's outcome, since each domain's `deliverToDomain` call
    /// catches every failure mode of its own and always returns data,
    /// never throws.
    private static func performDelivery(
        envelope: SMTPEnvelope, message: SignedMessage, resolver: any MXResolving, pool: SMTPConnectionPool,
        config: DirectMXConfig, retryQueueConfiguration: DirectMXRetryQueue.Configuration,
        mtaSTSPolicyProvider: (any MTASTSPolicyProviding)?, logger: Logger
    ) async -> [DeliveryResult] {
        let grouped = Dictionary(grouping: envelope.recipients, by: domain(of:))
        guard !grouped.isEmpty else { return [] }

        return await withTaskGroup(of: [DeliveryResult].self) { group in
            for (domain, recipients) in grouped {
                group.addTask {
                    await deliverToDomain(
                        domain, recipients: recipients, mailFrom: envelope.mailFrom, message: message,
                        resolver: resolver, pool: pool, config: config, retryQueueConfiguration: retryQueueConfiguration,
                        mtaSTSPolicyProvider: mtaSTSPolicyProvider, logger: logger
                    )
                }
            }
            var all: [DeliveryResult] = []
            for await results in group { all.append(contentsOf: results) }
            return all
        }
    }

    /// Resolves `domain`'s MX hosts, then attempts them in the resolver's
    /// returned preference/shuffle order, falling to the next host **only**
    /// on a connection-level failure (a dial failure, a circuit-open pool
    /// rejection, a mid-conversation disconnect) -- never on a message-
    /// level rejection from a host that did accept the connection (a `550`
    /// from the actual, connected, correct MX host is a real rejection for
    /// this domain, not a reason to try a different host; see
    /// `attemptOnHost`, which is what actually enforces this distinction by
    /// catching and *returning* (not rethrowing) `SMTPError`-classified
    /// rejections). That much is unchanged from Phase 3.
    ///
    /// Plan §9 Phase 4 adds MTA-STS policy (when `mtaSTSPolicyProvider` is
    /// configured) and the new opportunistic-TLS default (when
    /// `config.tlsPolicy == .opportunistic`) on top of that same host-
    /// fallback shape:
    ///
    /// - `config.tlsPolicy == .fixed(mode)`: **Phase 3 behavior, byte-for-
    ///   byte** -- every host tried with exactly `mode`, no MTA-STS lookup
    ///   at all (the explicit escape hatch `DirectMXTLSPolicy.fixed`'s doc
    ///   comment describes).
    /// - No MTA-STS policy for `domain` (no provider configured, or the
    ///   provider returned `nil`), or a policy with `mode: none`: every
    ///   host tried opportunistically (`.startTLS` first, `.none` fallback
    ///   -- see `attemptOpportunisticHostsInOrder`). This is also the exact
    ///   path `testing` mode falls back to below.
    /// - `mode: testing`: policy-matching hosts (RFC 8461 §4.1) are tried
    ///   first, mandatory-`.startTLS`-only, no plaintext fallback for those
    ///   attempts. If every matching host fails for a connection/TLS-level
    ///   reason (or there are no matching hosts at all), that's logged as a
    ///   testing-mode discrepancy and delivery falls through to the
    ///   ordinary opportunistic path across *all* resolved hosts --
    ///   `testing` mode must never block delivery (RFC 8461 §5, plan §9
    ///   Phase 4).
    /// - `mode: enforce`: **only** policy-matching hosts are ever dialed at
    ///   all, mandatory-`.startTLS`-only. If there are no matching hosts,
    ///   or every matching host fails for a connection/TLS-level reason,
    ///   the whole domain hard-fails with a distinct, `.permanentlyFailed`-
    ///   classified outcome (`mtaSTSEnforceViolationOutcome`) -- never a
    ///   silent degrade to plaintext or to a non-matching host.
    private static func deliverToDomain(
        _ domain: String, recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        resolver: any MXResolving, pool: SMTPConnectionPool, config: DirectMXConfig,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration,
        mtaSTSPolicyProvider: (any MTASTSPolicyProviding)?, logger: Logger
    ) async -> [DeliveryResult] {
        let hosts: [String]
        do {
            hosts = try await resolveMXHosts(domain: domain, resolver: resolver)
        } catch let resolveError as DNSResolver.ResolveError {
            let outcome = classify(resolveError: resolveError, domain: domain, retryQueueConfiguration: retryQueueConfiguration)
            return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }
        } catch {
            return recipients.map { DeliveryResult(recipient: $0, outcome: .failed(error)) }
        }

        var lastError: any Error = DirectMXError.noUsableMXHost(domain: domain)

        // `.fixed(mode)`: Phase 3's exact original loop, untouched -- no
        // MTA-STS lookup at all, no opportunistic fallback.
        if case .fixed(let mode) = config.tlsPolicy {
            if let results = await attemptHostsInOrder(
                hosts, keyForHost: { SMTPConnectionPool.Key(host: $0, port: config.port, tls: mode) },
                recipients: recipients, mailFrom: mailFrom, message: message,
                pool: pool, retryQueueConfiguration: retryQueueConfiguration, lastError: &lastError
            ) { return results }
            return recipients.map { DeliveryResult(recipient: $0, outcome: .failed(lastError)) }
        }

        if let mtaSTSPolicyProvider, let policy = await mtaSTSPolicyProvider.policy(for: domain), policy.mode != .none {
            let matchedHosts = hosts.filter { host in policy.mxPatterns.contains { MXPatternMatcher.matches(pattern: $0, host: host) } }

            switch policy.mode {
            case .enforce:
                guard !matchedHosts.isEmpty else {
                    logger.warning(
                        "MTA-STS enforce: no resolved MX host matches the policy's mx: patterns; hard-failing delivery",
                        metadata: ["domain": "\(domain)", "resolvedHosts": "\(hosts)", "mxPatterns": "\(policy.mxPatterns)"]
                    )
                    let outcome = mtaSTSEnforceViolationOutcome(domain: domain, reason: "no resolved MX host matches the policy's mx: patterns")
                    return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }
                }
                if let results = await attemptHostsInOrder(
                    matchedHosts, keyForHost: { SMTPConnectionPool.Key(host: $0, port: config.port, tls: .startTLS) },
                    recipients: recipients, mailFrom: mailFrom, message: message,
                    pool: pool, retryQueueConfiguration: retryQueueConfiguration, lastError: &lastError
                ) { return results }
                logger.warning(
                    "MTA-STS enforce: every policy-matched MX host failed a mandatory-TLS connection attempt; hard-failing delivery",
                    metadata: ["domain": "\(domain)", "matchedHosts": "\(matchedHosts)", "lastError": "\(lastError)"]
                )
                let outcome = mtaSTSEnforceViolationOutcome(domain: domain, reason: "every policy-matched MX host failed mandatory STARTTLS (last error: \(lastError))")
                return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }

            case .testing:
                if let results = await attemptHostsInOrder(
                    matchedHosts, keyForHost: { SMTPConnectionPool.Key(host: $0, port: config.port, tls: .startTLS) },
                    recipients: recipients, mailFrom: mailFrom, message: message,
                    pool: pool, retryQueueConfiguration: retryQueueConfiguration, lastError: &lastError
                ) { return results }
                logger.notice(
                    "MTA-STS testing: policy-matched mandatory-TLS delivery did not succeed (or no MX host matched); falling back to unconstrained opportunistic delivery -- testing mode never blocks delivery",
                    metadata: [
                        "domain": "\(domain)", "matchedHosts": "\(matchedHosts)",
                        "reason": matchedHosts.isEmpty ? "no MX host matched the policy's mx: patterns" : "\(lastError)",
                    ]
                )
                // Falls through to the unconstrained opportunistic path
                // below -- testing mode must never block delivery.

            case .none:
                break // unreachable: guarded by `policy.mode != .none` above; kept exhaustive.
            }
        }

        if let results = await attemptOpportunisticHostsInOrder(
            hosts, port: config.port, recipients: recipients, mailFrom: mailFrom, message: message,
            pool: pool, retryQueueConfiguration: retryQueueConfiguration, lastError: &lastError
        ) { return results }
        return recipients.map { DeliveryResult(recipient: $0, outcome: .failed(lastError)) }
    }

    /// Tries `hosts` in order, each with exactly `keyForHost(host)` -- no
    /// opportunistic fallback within a single host. Returns the first
    /// host's result once a connection is actually established and a mail
    /// transaction run against it (regardless of the SMTP-level outcome
    /// that transaction itself produced -- a real rejection from a
    /// connected host is a real outcome, not a reason to keep trying other
    /// hosts, matching `deliverToDomain`'s original Phase 3 contract), or
    /// `nil` if every host's own connection attempt failed (`lastError` is
    /// updated with the most recent failure either way, mirroring the
    /// original loop's `lastError` bookkeeping).
    private static func attemptHostsInOrder(
        _ hosts: [String], keyForHost: (String) -> SMTPConnectionPool.Key,
        recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        pool: SMTPConnectionPool, retryQueueConfiguration: DirectMXRetryQueue.Configuration,
        lastError: inout any Error
    ) async -> [DeliveryResult]? {
        for host in hosts {
            do {
                return try await attemptOnHost(
                    key: keyForHost(host), recipients: recipients, mailFrom: mailFrom, message: message,
                    pool: pool, retryQueueConfiguration: retryQueueConfiguration
                )
            } catch {
                lastError = error
                continue
            }
        }
        return nil
    }

    /// Plan §9 Phase 4 point 4: per host, try `.startTLS` first
    /// (mandatory-verified); on a genuine, non-injection connection/TLS
    /// failure, retry the **same host** with `.none` before moving on to
    /// the next resolved host. **Security-critical distinction (do not
    /// weaken):** a detected `SMTPError.starttlsInjection` on the
    /// `.startTLS` attempt never triggers the `.none` retry for that host
    /// -- it is exactly the downgrade-attack outcome the STARTTLS
    /// buffer-discipline design (plan §4.3) exists to prevent. An
    /// injection detection only ever advances to the *next resolved host*
    /// (ordinary host-level fallback, ultimately still subject to the same
    /// SSRF-class address filtering and circuit breaker as every other
    /// host attempt), never retries the same host unauthenticated.
    ///
    /// FIX #1 (milestone security review, CRITICAL -- the breaker-laundering
    /// finding): `SMTPError.circuitOpen` gets **exactly the same treatment**
    /// as `.starttlsInjection` here -- see
    /// `mustNeverTriggerAPlaintextRetryAgainstThisHost`'s doc comment for
    /// the full explanation of why. Do not special-case `.circuitOpen`
    /// separately from `.starttlsInjection` at this call site; they must
    /// stay behind the same guard so a future edit can't reintroduce the
    /// laundering gap by "fixing" only one of them.
    private static func attemptOpportunisticHostsInOrder(
        _ hosts: [String], port: Int, recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        pool: SMTPConnectionPool, retryQueueConfiguration: DirectMXRetryQueue.Configuration,
        lastError: inout any Error
    ) async -> [DeliveryResult]? {
        for host in hosts {
            let startTLSKey = SMTPConnectionPool.Key(host: host, port: port, tls: .startTLS)
            do {
                return try await attemptOnHost(
                    key: startTLSKey, recipients: recipients, mailFrom: mailFrom, message: message,
                    pool: pool, retryQueueConfiguration: retryQueueConfiguration
                )
            } catch {
                lastError = error
                if mustNeverTriggerAPlaintextRetryAgainstThisHost(error) {
                    // Never fall back to plaintext after a detected
                    // injection attack against this host, or after the
                    // pool's circuit breaker opened for this host's
                    // `.startTLS` key for *any* reason (including, but not
                    // limited to, a run of injection detections) -- move on
                    // to the next resolved MX host instead, exactly like
                    // any other host-level connection failure.
                    continue
                }
                let plaintextKey = SMTPConnectionPool.Key(host: host, port: port, tls: .none)
                do {
                    return try await attemptOnHost(
                        key: plaintextKey, recipients: recipients, mailFrom: mailFrom, message: message,
                        pool: pool, retryQueueConfiguration: retryQueueConfiguration
                    )
                } catch {
                    lastError = error
                    continue
                }
            }
        }
        return nil
    }

    /// `true` for a genuine, detected STARTTLS-injection attempt (RFC 5321
    /// STARTTLS buffer-discipline violation, plan §4.3) **or** for
    /// `SMTPError.circuitOpen`. Every other thrown error (absence of
    /// STARTTLS support, a legitimate certificate/handshake failure, a
    /// plain connection error) returns `false` and is treated as an
    /// ordinary opportunistic-fallback trigger (try the same host in
    /// plaintext).
    ///
    /// FIX #1 (milestone security review, CRITICAL -- "the circuit breaker
    /// launders a detected STARTTLS-injection attack into a silent
    /// plaintext downgrade"): before this fix, only `.starttlsInjection`
    /// was excluded here. `SMTPConnectionPool`'s breaker check throws a bare
    /// `SMTPError.circuitOpen` -- with **no** associated value carrying
    /// *why* the breaker opened -- and `SMTPConnectionPool.checkout` calls
    /// `recordFailure(key)` on every dial failure uniformly, including a
    /// detected `.starttlsInjection` (see `checkout`'s `catch` clause and
    /// `attemptOnHost`'s doc comment: an injection detection propagates
    /// through the dialer/pool exactly like any other dial failure once it
    /// reaches `SMTPConnectionPool`, which has no injection-specific
    /// bookkeeping of its own).
    ///
    /// That means an attacker able to intercept every connection attempt to
    /// a host needs only `circuitBreakerThreshold` (default 5) consecutive
    /// injection attempts -- trivially reachable across a handful of
    /// recipients or retries within seconds -- to flip that host's
    /// `Key(host, port, tls: .startTLS)` breaker open. Once open,
    /// the pool rejects with `.circuitOpen` *before ever dialing
    /// again*, so the previous code here (which only pattern-matched
    /// `.starttlsInjection` specifically) fell through to the plaintext-
    /// retry branch and connected the **same attacker-controlled host**
    /// with `TLSMode.none` -- laundering a confirmed downgrade attack into
    /// a normal `.delivered` outcome with no logging at all.
    ///
    /// `.circuitOpen` is **inherently ambiguous about root cause** -- the
    /// breaker aggregates every kind of dial failure (timeouts, refused
    /// connections, TLS failures, injection detections) into one
    /// consecutive-failure counter with no distinction. Because it *might*
    /// mean "this host is actively hostile," it must be treated as if it
    /// always does: never as a legitimate trigger for an opportunistic
    /// plaintext retry. A circuit-open host that's merely flaky/overloaded
    /// (the common, non-adversarial case) loses nothing meaningful by not
    /// getting a plaintext retry either -- `deliverToDomain`'s ordinary
    /// host-level fallback (try the next resolved MX host, or fail the
    /// domain if none remain) already covers that case correctly.
    private static func mustNeverTriggerAPlaintextRetryAgainstThisHost(_ error: any Error) -> Bool {
        switch error {
        case SMTPError.starttlsInjection, SMTPError.circuitOpen:
            return true
        default:
            return false
        }
    }

    /// Plan §9 Phase 4's "enforce-mode hard-fail" requirement: a distinct,
    /// clearly-classified `.permanentlyFailed` outcome -- never
    /// `.queuedForRetry` (an MTA-STS enforce violation is a policy
    /// decision, not a transient server condition retrying would resolve)
    /// and never silently downgraded to plaintext or a non-matching host.
    /// RFC 8461 itself defines no SMTP-level reply code for this (the
    /// violation is detected before/around the SMTP conversation, at the
    /// TLS-policy layer) -- `550 5.7.1` is this library's own conventional
    /// choice (a generic, widely-recognized "delivery not authorized,
    /// security policy" enhanced status), matching the precedent this
    /// codebase already set for its own non-RFC-mandated synthesized
    /// replies (e.g. `classify(resolveError:)`'s `556 5.1.10` for null-MX).
    private static func mtaSTSEnforceViolationOutcome(domain: String, reason: String) -> DeliveryResult.Outcome {
        .permanentlyFailed(SMTPReply(code: 550, lines: ["5.7.1 MTA-STS enforce policy violation for domain \(domain): \(reason)"]))
    }

    /// Checks out (dialing if needed) a pooled connection to `key` and runs
    /// one full mail transaction against it. A message-level rejection
    /// (`SMTPError`, thrown by `SMTPConnection.sendMessage` only when
    /// `MAIL FROM` itself is rejected -- individual `RCPT`/`DATA`-phase
    /// rejections are already returned as per-recipient `DeliveryResult`
    /// data by `sendMessage`, never thrown) is caught here and turned into
    /// normally-*returned* per-recipient outcomes instead of being
    /// rethrown -- this is what makes `deliverToDomain`'s host-fallback
    /// loop treat it as "handled" rather than "this host failed, try the
    /// next one." Any other thrown error (a dial failure inside
    /// `pool.withConnection`, `SMTPError.circuitOpen`, a mid-conversation
    /// `SMTPConnectionError`) propagates unchanged, which is exactly what
    /// signals "connection failure, fall back" to the caller.
    ///
    /// FIX (milestone architecture + SMTP-protocol reviews, converged on
    /// the same root cause): "handled, don't fall back to another host"
    /// and "the connection itself is still healthy" are **not** the same
    /// question -- a mid-DATA disconnect (`.ambiguous`) or a `421`
    /// ("closing the transmission channel," RFC 5321 §4.2.1) both return
    /// normally from this method (correctly -- neither should trigger
    /// MX-host fallback) but must **not** be treated as `healthy: true` by
    /// the pool, or a host that's flaky specifically in that window would
    /// never trip the circuit breaker. `isHealthy:` (passed to
    /// `pool.withConnection` below) is what closes that gap -- see
    /// `SMTPConnectionPool.deliveryResultsIndicateHealthyConnection`'s doc
    /// comment.
    private static func attemptOnHost(
        key: SMTPConnectionPool.Key, recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        pool: SMTPConnectionPool, retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) async throws -> [DeliveryResult] {
        try await pool.withConnection(to: key, isHealthy: SMTPConnectionPool.deliveryResultsIndicateHealthyConnection) { connection in
            let envelope = try SMTPEnvelope(mailFrom: mailFrom, recipients: recipients, size: message.estimatedSize)
            do {
                return try await connection.sendMessage(envelope, message)
            } catch let error as SMTPError {
                let outcome = classify(smtpError: error, retryQueueConfiguration: retryQueueConfiguration)
                return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }
            }
        }
    }

    // MARK: - MX resolution helpers

    /// Resolves `domain`'s MX exchange hostnames, in the resolver's
    /// preference/shuffle order, falling back to the RFC 5321 §5.1
    /// implicit-MX behavior (treat the domain's own A/AAAA records as its
    /// MX) when there are no MX records at all -- `DNSResolver` itself
    /// deliberately leaves this fallback decision to this caller (see that
    /// type's doc comment on `resolveMX(domain:)`). No special A/AAAA
    /// lookup happens *here* for that fallback: returning `[domain]` as
    /// the sole candidate host is sufficient, because `makeDialer`'s own
    /// dialer resolves whatever hostname it's asked to connect to via
    /// `resolver.resolveAddresses(hostname:)` regardless of whether that
    /// hostname came from an MX record or is the domain itself -- if the
    /// domain genuinely has no A/AAAA either, that surfaces naturally as a
    /// dial failure on this one candidate host, handled the same as any
    /// other host-level failure.
    ///
    /// `.nullMX` (RFC 7505) is deliberately **not** caught here -- it
    /// propagates to `deliverToDomain`'s caller, which hard-fails the whole
    /// domain via `classify(resolveError:domain:)` without ever reaching
    /// this fallback. That is the entire point of null-MX.
    private static func resolveMXHosts(domain: String, resolver: any MXResolving) async throws -> [String] {
        do {
            let records = try await resolver.resolveMX(domain: domain)
            return records.map(\.exchange)
        } catch DNSResolver.ResolveError.noRecordsFound {
            return [domain]
        }
    }

    /// - Parameters:
    ///   - retryQueueConfiguration: Threaded through only for `.timeout`/
    ///     `.serverFailure`/`.noNameserversConfigured` (see that `case`'s
    ///     comment below) -- everything else this method classifies is
    ///     permanent and never touches a backoff policy at all.
    private static func classify(
        resolveError: DNSResolver.ResolveError, domain: String, retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) -> DeliveryResult.Outcome {
        switch resolveError {
        case .nullMX:
            // RFC 7505: an explicit, authoritative "this domain does not
            // accept email at all" -- hard-fail permanently, never fall
            // through to A/AAAA. 556 5.1.10 is the RFC-conventional code
            // for exactly this condition.
            return .permanentlyFailed(SMTPReply(code: 556, lines: ["5.1.10 Domain \(domain) does not accept email (null MX record, RFC 7505)"]))
        case .noRecordsFound:
            // Only reachable here if the RFC 5321 §5.1 implicit-MX
            // fallback itself later fails to resolve any A/AAAA for
            // `domain` either -- `resolveMXHosts` intercepts a
            // `.noRecordsFound` MX lookup and falls through to the
            // address-fallback path (returning `[domain]`) instead of
            // rethrowing it, so in the common case this specific branch of
            // `classify` is unreachable; the "no MX and no A/AAAA at all"
            // outcome instead surfaces through `deliverToDomain`'s ordinary
            // host-fallback-exhausted path as `.failed`, not here. Kept for
            // exhaustiveness / defense-in-depth in case that call site's
            // behavior changes.
            return .permanentlyFailed(SMTPReply(code: 550, lines: ["5.1.2 Domain \(domain) has no MX records"]))
        case .timeout, .serverFailure, .noNameserversConfigured:
            // Milestone review finding (architecture + SMTP-protocol
            // reviews, independently flagged): a genuine DNS-*infrastructure*
            // problem (a resolver that didn't answer in time, an
            // authoritative server returning SERVFAIL/REFUSED, or this
            // process having no nameservers configured at all) is plausibly
            // transient -- a network blip, a resolver restart -- and says
            // nothing about whether `domain` itself accepts mail. Treating
            // it as immediately, permanently `.failed` (the previous
            // behavior) discarded that distinction; routed through the
            // retry queue instead, via a synthesized `SMTPReply` (RFC 3463
            // enhanced status `4.4.3`, "directory server failure" -- the
            // conventional code real MTAs use for exactly this: a
            // temporary DNS lookup failure) so `retryQueueConfiguration`'s
            // already-configured backoff machinery classifies it uniformly
            // with every other transient outcome (a `450`-class reply
            // lands on the same conservative `greylist` backoff duration
            // Phase 1's own RCPT/DATA-phase rejections use for an
            // equivalent-severity failure).
            let reply = SMTPReply(code: 450, lines: ["4.4.3 Temporary DNS resolution failure for \(domain) (\(resolveError))"])
            return retryQueueConfiguration.classify(reply, attempt: 1)
        case .malformedResponse, .cnameLoop:
            // Unlike the infrastructure failures above, these indicate the
            // *queried* nameserver actually responded but with something
            // this codec can't safely use (a malformed wire-format message,
            // or a CNAME chain that couldn't be safely followed to
            // completion) -- not obviously transient the way a timeout or
            // SERVFAIL is, so left exactly as before: `.failed`, not
            // auto-retried, not guessed to be permanent either.
            return .failed(resolveError)
        }
    }

    /// Classifies an `SMTPError` thrown by `SMTPConnection.sendMessage`
    /// (always a `MAIL FROM`-level rejection in practice -- see
    /// `attemptOnHost`'s doc comment) into a `DeliveryResult.Outcome`,
    /// using `retryQueueConfiguration`'s real backoff durations rather than
    /// any hardcoded placeholder, so a `MAIL FROM`-level `421`/greylist
    /// rejection gets the exact same configured backoff a `RCPT`-level one
    /// would. This is only symmetric with `RCPT`/`DATA`-phase outcomes
    /// (classified inside `SMTPConnection.outcomeFor` itself, not here)
    /// because `makeDialer` passes this same `retryQueueConfiguration
    /// .backoff` policy to every `SMTPConnection` it dials -- see that
    /// method's comment and `SMTPConnection.backoffPolicy`'s doc comment.
    private static func classify(smtpError: SMTPError, retryQueueConfiguration: DirectMXRetryQueue.Configuration) -> DeliveryResult.Outcome {
        switch smtpError {
        case .permanentFailure(let reply):
            return .permanentlyFailed(reply)
        case .transientFailure(let reply), .greylisted(let reply), .serviceUnavailable(let reply):
            return retryQueueConfiguration.classify(reply, attempt: 1)
        case .sizeExceeded:
            // No `SMTPReply` survives past `classifyMailFromFailure`'s
            // `552` -> `.sizeExceeded` mapping to attach here -- the
            // message is simply too large for this destination; retrying
            // won't change that, so this is permanent.
            return .permanentlyFailed(SMTPReply(code: 552, lines: ["5.3.4 Message size exceeds server limit"]))
        case .authenticationFailed(let reply):
            // `DirectMXTransport` never authenticates (direct-MX delivery
            // has no relay credentials to present) -- unreachable in
            // practice; handled defensively rather than assumed impossible.
            return .permanentlyFailed(reply)
        case .ambiguousDelivery(let reply):
            // Never queued for retry -- `DirectMXRetryQueue.enqueue`'s own
            // guard only ever schedules `.queuedForRetry`, so returning
            // `.ambiguous` here is sufficient on its own to guarantee this
            // never gets auto-retried.
            return .ambiguous(reply)
        case .starttlsRequired, .starttlsInjection, .tlsPolicyViolation, .circuitOpen, .connectionFailed:
            // None of these are reply-classified rejections from a
            // connected peer -- they're connection/policy-level failures
            // that, in practice, are thrown by the pool's own dial path or
            // STARTTLS bootstrap (inside `pool.withConnection`'s dialer),
            // never by `SMTPConnection.sendMessage` itself, so
            // `attemptOnHost`'s `catch let error as SMTPError` should never
            // actually observe one of these cases. Handled defensively --
            // `.failed` is the correct "not reply-classified" bucket
            // regardless of how it got here.
            return .failed(smtpError)
        }
    }

    /// The production dialer: resolves `key.host`'s A/AAAA addresses via
    /// `resolver` (real DNS in production), then tries connecting to each
    /// returned address in turn (first success wins) -- a second, finer-
    /// grained fallback layer underneath `deliverToDomain`'s MX-host-level
    /// fallback, for hosts that themselves have multiple A/AAAA records.
    ///
    /// **Why this reuses `SMTPConnectionPool` rather than a second pool
    /// type:** the plan called for "a second connection pool... reuse
    /// `SMTPConnectionPool` directly if its existing `Key`/`withConnection`
    /// shape already fits." It does: `Key { host, port, tls }` has no
    /// relay-specific assumption baked in (it's already exactly "one
    /// destination, keyed by where to connect and how to secure it"), and
    /// the one piece that genuinely differs between `RelayTransport` and
    /// `DirectMXTransport` -- *how a `Key` turns into a live connection* --
    /// is precisely the seam `SMTPConnectionPool` already exposes via its
    /// internal `dialer` closure (originally added, per that type's own
    /// comments, purely as a test seam for Phase 1, but it turns out to be
    /// exactly the right production seam here too: a direct-MX dialer that
    /// resolves-then-connects instead of a relay dialer that just
    /// connects). Circuit breaking, idle eviction, and the reentrancy-safe
    /// checkout/waiter machinery are all identically correct for "many
    /// destination hosts" as they are for "one configured relay host" --
    /// none of it assumes a single fixed destination anywhere in
    /// `SMTPConnectionPool.swift`. So this is a second pool *instance*
    /// (`DirectMXTransport` owns its own, separate from any
    /// `RelayTransport` a caller might also have), not a second pool
    /// *implementation*.
    private static func makeDialer(
        resolver: any MXResolving, config: DirectMXConfig, group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) -> @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection {
        { key in
            let resolvedAddresses = try await resolver.resolveAddresses(hostname: key.host)
            // FIX #2 (milestone security review, SSRF-class filtering):
            // drop every address in a private/loopback/link-local/
            // unique-local/CGNAT range before ever dialing it -- see
            // `DNSAddress.isRoutable`'s doc comment for the exact ranges
            // and `DirectMXConfig.allowPrivateAddresses`'s doc comment for
            // the attack this protects against and the documented
            // opt-out.
            let addresses = config.allowPrivateAddresses ? resolvedAddresses : resolvedAddresses.filter(\.isRoutable)
            guard !addresses.isEmpty else {
                // Distinguish "the resolver returned nothing at all" from
                // "every candidate was filtered as private/reserved" --
                // the latter is a real, actionable security-relevant
                // outcome (this host published an address this transport
                // refuses to dial), not a mysterious connection failure.
                if !config.allowPrivateAddresses, !resolvedAddresses.isEmpty {
                    throw DirectMXError.allResolvedAddressesFilteredAsPrivate(host: key.host)
                }
                throw DirectMXError.noUsableAddress(host: key.host)
            }
            var lastError: any Error = DirectMXError.noUsableAddress(host: key.host)
            for address in addresses {
                do {
                    let socketAddress = try SocketAddress(ipAddress: address.description, port: key.port)
                    let asyncChannel = try await SMTPBootstrap.connect(
                        to: socketAddress, sniHostname: key.host, tls: key.tls,
                        connectTimeout: config.connectTimeout, replyTimeout: config.replyTimeout, group: group
                    )
                    let connection = SMTPConnection(
                        asyncChannel: asyncChannel, ehloHostname: config.ehloHostname,
                        replyTimeout: config.replyTimeout, dataTerminationTimeout: config.dataTerminationTimeout,
                        // Same configured backoff policy this transport's
                        // retry queue itself uses (see
                        // `DirectMXRetryQueue.Configuration.backoff`'s doc
                        // comment) -- a RCPT/DATA-phase rejection
                        // classified inside `SMTPConnection.outcomeFor` and
                        // a MAIL-FROM-phase rejection classified by
                        // `DirectMXTransport.classify(smtpError:...)` get
                        // identical backoff durations for identical reply
                        // codes.
                        backoffPolicy: retryQueueConfiguration.backoff
                    )
                    do {
                        try await connection.negotiateCapabilities()
                    } catch {
                        // Close and wait before throwing (or trying the
                        // next address): the pool frees this dial's slot
                        // as soon as the dialer throws.
                        await connection.closeAndWait()
                        throw error
                    }
                    return connection
                } catch let error as SMTPError {
                    // Plan §9 Phase 4 security requirement: a detected
                    // STARTTLS-injection attack against *this* address must
                    // never be masked by trying another address for the
                    // same host and reporting only that later, possibly
                    // benign, error as `lastError` -- surfacing it
                    // immediately (rather than letting the per-address loop
                    // continue) is what lets `deliverToDomain`'s
                    // opportunistic-TLS fallback
                    // (`attemptOpportunisticHostsInOrder`) correctly refuse
                    // to retry this host with `TLSMode.none` after an
                    // injection detection -- if a later, unrelated
                    // address's ordinary connection failure were allowed to
                    // overwrite `lastError` here, that caller would never
                    // see the injection and could wrongly fall back to
                    // plaintext.
                    if case .starttlsInjection = error { throw error }
                    lastError = error
                    continue
                } catch {
                    lastError = error
                    continue
                }
            }
            throw lastError
        }
    }

    /// Extracts the domain (the part after the last unescaped `@`) from an
    /// `addr-spec` string, lowercased for grouping (DNS names are
    /// case-insensitive; the recipient string itself, used verbatim in
    /// `RCPT TO`, is never mutated). Deliberately a plain
    /// last-`@`-occurrence split, not a full RFC 5321 `addr-spec`-grammar-
    /// aware parse (which would need to understand quoted local parts that
    /// can themselves contain `@`) -- matching this codebase's existing
    /// scoping discipline elsewhere (e.g. `SMTPEnvelope`'s own recipient
    /// validation only checks for header-injection characters, not full
    /// grammar conformance).
    private static func domain(of recipient: String) -> String {
        guard let atIndex = recipient.lastIndex(of: "@") else { return recipient.lowercased() }
        return String(recipient[recipient.index(after: atIndex)...]).lowercased()
    }
}

//
//  MTASTSPolicyManager.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: discovery (`_mta-sts.<domain>` TXT lookup) + fetch
//  (HTTPS GET of the well-known policy file) + parse + cache, wired
//  together as one actor so `DirectMXTransport` has a single
//  `policy(for:)` call to make per destination domain.
//
//  **Scope boundary -- in-memory only, deliberately (stated explicitly, not
//  silently omitted, matching this codebase's established precedent --
//  see `DirectMXRetryQueue.swift`'s own header comment for the exact same
//  pattern applied to its retry-entry cache): this is a library, not a
//  standalone daemon.** Every cached policy lives only in this actor's own
//  `cache` dictionary, for the lifetime of the process. A caller wanting
//  durable policy-cache persistence across process restarts (so every
//  domain doesn't re-fetch its policy on the first send after a restart)
//  must build that themselves on top of this API. Nothing here reads or
//  writes disk, a database, or any other durable store.
//

import Foundation

/// The seam `DirectMXTransport` depends on -- `MTASTSPolicyManager` in
/// production, a fake in tests that don't want real DNS/HTTPS involved at
/// all (mirroring `MXResolving`'s role for `DNSResolver`).
public protocol MTASTSPolicyProviding: Sendable {
    /// Returns the current usable policy for `domain`, or `nil` if this
    /// domain has no usable MTA-STS policy right now -- no TXT-record
    /// discovery signal, an HTTPS fetch failure with nothing usable cached,
    /// or a policy file that failed to parse. Never throws: per RFC 8461
    /// §3.3 and plan §9 Phase 4's explicit instruction, every failure
    /// mode here degrades to "treat this domain as policy-less" rather than
    /// surfacing as an error `DirectMXTransport` would have to specially
    /// handle -- MTA-STS is opportunistic-by-nature at the discovery layer,
    /// even though `enforce`/`testing` policies (once successfully
    /// obtained) are not.
    func policy(for domain: String) async -> MTASTSPolicy?
}

/// Errors specific to this actor's own discovery/fetch/parse pipeline (as
/// opposed to `TXTResolving`/`MTASTSHTTPFetching`'s own lower-level errors,
/// which this type catches and folds into one of these instead of letting
/// callers reach into transport-specific failure detail they don't need).
enum MTASTSDiscoveryError: Error, Sendable, Equatable {
    /// FIX A (protocol review): covers every way RFC 8461 §3.1's "exactly
    /// one, syntactically valid" gate can fail -- no TXT record at all,
    /// more than one TXT record (an ambiguous discovery result the RFC
    /// explicitly says MUST be treated as "no policy", not "pick one"),
    /// or a single record that isn't a syntactically valid `v=STSv1;
    /// id=...` string. This is by far the ordinary, expected outcome for
    /// the vast majority of domains, which simply don't publish MTA-STS at
    /// all -- not just the zero-records case.
    case noSTSv1DiscoveryRecord
    /// The HTTPS fetch itself failed: a network/TLS error, or a non-200
    /// status code (RFC 8461 §3.3).
    case fetchFailed
    /// The response's `Content-Type` wasn't `text/plain` (RFC 8461 §3.2).
    case invalidContentType
    /// FIX C (protocol review): the response body exceeded
    /// `MTASTSPolicyManager.maximumPolicyResponseSizeBytes` (RFC 8461 §3.3
    /// SHOULD, 64KB) -- folded into "fetch failed" from every caller's
    /// perspective (falls back to a valid cached policy if one exists, per
    /// `policy(for:)`'s existing fallback logic) rather than given its own
    /// externally-visible handling, but kept as a distinct case here for
    /// diagnosability.
    case responseTooLarge
    /// FIX D (protocol review, option (a)): every address
    /// `addressResolver` resolved for the MTA-STS HTTPS fetch hostname
    /// (`mta-sts.<domain>`) was filtered out as private/loopback/link-
    /// local/unique-local/CGNAT (see `DNSAddress.isRoutable`) -- mirrors
    /// `DirectMXError.allResolvedAddressesFilteredAsPrivate`'s identical
    /// treatment of the direct-MX dial path. Never thrown when
    /// `addressResolver` is `nil` (SSRF filtering not configured) or when
    /// `Configuration.allowPrivateAddresses` is `true`.
    case addressFilteredAsPrivate
    /// The response body didn't parse as a valid policy file
    /// (`MTASTSPolicyParser.parse(_:)` returned `nil`).
    case malformedPolicy
}

/// Discovers, fetches, parses, and caches MTA-STS policies per destination
/// domain (RFC 8461). Concurrency-safe by construction (an actor, per this
/// codebase's established shape for stateful, checkout-style components --
/// mirrors `SMTPConnectionPool`/`DirectMXRetryQueue`'s own precedent).
public actor MTASTSPolicyManager: MTASTSPolicyProviding {
    private struct CachedPolicy {
        let policy: MTASTSPolicy
        let expiresAt: Date
        /// FIX B (protocol review): the discovery TXT record's `id=` token
        /// (RFC 8461 §3.1) captured at the moment this entry was fetched --
        /// compared against a fresh TXT lookup's `id` on each due
        /// `idRecheckInterval` cadence (see `policy(for:)`) so a domain
        /// that publishes a policy update faster than this entry's own
        /// `max_age` still gets picked up.
        let discoveryID: String
        /// FIX B: when this entry's `id` was last verified against a live
        /// TXT lookup (as opposed to `expiresAt`, which tracks the
        /// unrelated `max_age`-based full-policy expiry). Starts equal to
        /// the fetch time; bumped forward on every id-recheck, whether the
        /// id matched or the recheck was inconclusive (see `policy(for:)`).
        var lastIDCheckedAt: Date
    }

    /// FIX B (protocol review): one successfully parsed discovery TXT
    /// record (RFC 8461 §3.1's `v=STSv1; id=<token>; ...`), reduced to just
    /// the `id` value this manager actually needs -- returned by
    /// `discoverValidRecord(domain:)`, the single place both a full fetch
    /// and a cheap id-only recheck go through, so FIX A's "exactly one,
    /// syntactically valid" gate is enforced identically either way.
    private struct DiscoveryRecord: Sendable, Equatable {
        let id: String
    }

    /// One fully fetched-and-parsed policy, plus the discovery record's
    /// `id` it was fetched under -- what `fetchAndParsePolicy(domain:)`
    /// returns, so `policy(for:)` can populate `CachedPolicy.discoveryID`
    /// without a second TXT lookup.
    private struct FetchedPolicy {
        let policy: MTASTSPolicy
        let discoveryID: String
    }

    /// FIX #2 / FIX #4 (milestone architecture + security review, both
    /// resolved the same way `DirectMXRetryQueue.Configuration` resolved
    /// the equivalent-shaped problems for that actor's own cache -- see
    /// that type's `maxAge`/`maxTotalEntries` doc comments for the
    /// established precedent this mirrors).
    public struct Configuration: Sendable {
        /// FIX #2 (milestone architecture review, BLOCKING): how long past
        /// a cached policy's own `expiresAt` (`CachedPolicy.expiresAt`,
        /// `now()` at fetch time plus that policy's own RFC 8461 §3.2
        /// `max_age`) this manager will still trust and apply it after a
        /// *subsequent* discovery/fetch/parse failure, before instead
        /// reverting the domain to policy-less.
        ///
        /// **This is this library's own explicit, reviewed policy
        /// decision, not an RFC 8461 requirement** -- RFC 8461 itself
        /// specifies no shape for it (see `policy(for:)`'s doc comment for
        /// the actual RFC text this behavior is grounded in, and why the
        /// previous doc comment's "§5.1 anti-flapping" citation was wrong).
        /// Named and recorded here the same way this codebase's DANE-
        /// deferral decision was recorded in
        /// `Documentation/swift6-nio-rewrite-plan.md` §9's Phase 4 bullet
        /// (see that document's corresponding entry for this decision).
        ///
        /// Default 5 days (432,000s) -- deliberately matching
        /// `DirectMXRetryQueue.Configuration.maxAge`'s own default and
        /// rationale (conventional MTA give-up windows, e.g. Postfix's
        /// `maximal_queue_lifetime` default) for consistency across this
        /// codebase's two "how long do we keep trusting stale state"
        /// decisions, not because RFC 8461 mentions this number anywhere.
        /// A domain that has been unreachable (DNS or HTTPS) for 5
        /// straight days is past the point where "assume the old policy
        /// still applies" is a reasonable default; a domain that
        /// legitimately decommissioned MTA-STS during that window instead
        /// reverts to policy-less and delivery can proceed against
        /// whatever its current, real MX hosts are.
        public var staleCacheCeiling: TimeInterval
        /// FIX #4 (MEDIUM security, milestone security review): a hard
        /// ceiling on how many distinct domains' policies this actor will
        /// cache at once -- mirroring
        /// `DirectMXRetryQueue.Configuration.maxTotalEntries`'s identical
        /// concern (a long-lived process with no cap here would grow this
        /// dictionary unboundedly, one entry per distinct domain ever
        /// queried, for the lifetime of the process). Default 10,000,
        /// matching `maxTotalEntries`'s own default for the same
        /// consistency reason `staleCacheCeiling` matches `maxAge`.
        ///
        /// Eviction policy when a new entry would exceed this cap: evict
        /// the cached entry with the earliest `expiresAt` first -- a
        /// cheap, O(n) approximation of LRU (no separate access-order
        /// bookkeeping needed) that fits this actor's existing shape.
        /// "Earliest `expiresAt`" is a reasonable proxy for "least
        /// recently useful" here specifically because every cache write
        /// sets `expiresAt` to a fresh `now() + max_age` -- a domain that
        /// hasn't been re-fetched (i.e., re-queried) in a while is exactly
        /// the one whose `expiresAt` has drifted furthest into the past
        /// relative to its peers.
        public var maxCacheEntries: Int
        /// FIX B (protocol review): how often a still-`max_age`-valid
        /// cached entry's discovery `id` is re-verified against a fresh
        /// `_mta-sts.<domain>` TXT lookup, per RFC 8461 §3.1 ("senders
        /// need only check the TXT record's version 'id' against the
        /// cached value") and §3.3's suggested cadence ("once per day").
        /// Deliberately **not** the same knob as `staleCacheCeiling` or a
        /// policy's own `max_age` -- this is a much cheaper, much more
        /// frequent-relative-to-nothing check (one TXT lookup, no HTTPS
        /// fetch) than a full refresh, and doing it on every single
        /// `policy(for:)` call would defeat the entire point of caching
        /// (one DNS round-trip per send instead of zero). Default 24
        /// hours, directly matching RFC 8461 §3.3's own suggested cadence
        /// rather than an unrelated number borrowed from elsewhere in this
        /// codebase.
        ///
        /// A cached entry whose `lastIDCheckedAt` is still within this
        /// interval is returned from the fast path with **zero** network
        /// calls, exactly as before this fix -- only once the interval has
        /// elapsed does `policy(for:)` spend one TXT lookup confirming the
        /// `id` hasn't changed before continuing to trust the cached
        /// policy body.
        public var idRecheckInterval: TimeInterval
        /// Governs the optional `addressResolver` pre-check only; the
        /// default `NIOMTASTSHTTPFetcher` has its own flag. Mirrors
        /// `DirectMXConfig.allowPrivateAddresses` for the MTA-STS fetch --
        /// `false` (filtering on) by default, since the same "attacker
        /// controls the recipient domain" threat model
        /// `DirectMXConfig`'s own doc comment describes applies equally to
        /// `mta-sts.<domain>`. Only takes effect when `addressResolver` is
        /// non-`nil` (see `MTASTSPolicyManager.init`'s doc comment) -- with
        /// no address resolver configured, there is nothing for this flag
        /// to modulate.
        public var allowPrivateAddresses: Bool

        public init(
            staleCacheCeiling: TimeInterval = 5 * 24 * 3600,
            maxCacheEntries: Int = 10_000,
            idRecheckInterval: TimeInterval = 24 * 3600,
            allowPrivateAddresses: Bool = false
        ) {
            self.staleCacheCeiling = staleCacheCeiling
            self.maxCacheEntries = maxCacheEntries
            self.idRecheckInterval = idRecheckInterval
            self.allowPrivateAddresses = allowPrivateAddresses
        }
    }

    /// RFC 8461 §3.3 SHOULD: "a maximum size for the policy file" -- FIX C
    /// (protocol review). 64KB, deliberately matching `SMTPBootstrap
    /// .maximumReplyBufferSize`'s identical discipline elsewhere in this
    /// codebase for the same reason: a real MTA-STS policy file (a handful
    /// of `key: value` lines, at most a few dozen `mx:` patterns) is never
    /// remotely close to this size, so the cap is pure DoS hardening with
    /// no legitimate-policy cost. The default `NIOMTASTSHTTPFetcher`
    /// enforces it while streaming (and rejects a larger `Content-Length` up front), so
    /// an endless body is never buffered; `fetchAndParsePolicy(domain:)`
    /// checks it again for any other `MTASTSHTTPFetching` implementation.
    public static let maximumPolicyResponseSizeBytes = 64 * 1024

    private var cache: [String: CachedPolicy] = [:]
    private let dnsResolver: any TXTResolving
    private let httpFetcher: any MTASTSHTTPFetching
    /// FIX D (protocol review, option (a)): `nil` (the default) means the
    /// MTA-STS HTTPS fetch target is never pre-checked against
    /// `DNSAddress.isRoutable` before this manager attempts the fetch --
    /// the same "purely additive opt-in" shape `DirectMXTransport`'s own
    /// `mtaSTSPolicyProvider` uses (see that property's doc comment): a
    /// caller who doesn't pass this gets no new network dependency (no
    /// extra DNS round-trip before every cache-miss fetch) and no behavior
    /// change from this fix. **A caller integrating this library with
    /// untrusted recipient input should pass a real `MTASTSAddressResolving`
    /// (a `DNSResolver`, which already conforms) here** -- exactly the same
    /// "attacker controls the recipient domain" threat model
    /// `DirectMXConfig`'s doc comment describes for the direct-MX dial path
    /// applies identically to the `https://mta-sts.<domain>/...` fetch this
    /// manager performs, and leaving this `nil` leaves that fetch
    /// unprotected by the address filtering this codebase otherwise treats
    /// as a first-class concern.
    private let addressResolver: (any MTASTSAddressResolving)?
    private let configuration: Configuration
    /// Injectable purely for deterministic cache-expiry tests (mirroring
    /// this codebase's other "inject the clock" test seams, e.g.
    /// `SMTPConnectionPool`'s own `ContinuousClock` field) -- production
    /// always uses `Date.init` (the real wall clock).
    private let now: @Sendable () -> Date

    /// - Parameter httpFetcher: Defaults to `NIOMTASTSHTTPFetcher()`, which
    ///   resolves the policy host itself, refuses non-routable addresses,
    ///   dials only a vetted address and caps the body. To allow private
    ///   addresses with it, pass `NIOMTASTSHTTPFetcher(allowPrivateAddresses:
    ///   true)`; `Configuration.allowPrivateAddresses` only governs the
    ///   pre-check below.
    /// - Parameter addressResolver: An extra pre-check for custom fetchers
    ///   that can't vet addresses themselves (see the stored property's doc
    ///   comment). `nil` by default; the default fetcher doesn't need it.
    public init(
        dnsResolver: any TXTResolving,
        httpFetcher: any MTASTSHTTPFetching = NIOMTASTSHTTPFetcher(),
        addressResolver: (any MTASTSAddressResolving)? = nil,
        configuration: Configuration = .init()
    ) {
        self.init(
            dnsResolver: dnsResolver, httpFetcher: httpFetcher, addressResolver: addressResolver,
            configuration: configuration, now: Date.init
        )
    }

    /// Test/internal-only initializer: overrides the clock so cache-expiry
    /// tests don't need real `Task.sleep` waits proportional to a
    /// realistic `max_age`.
    init(
        dnsResolver: any TXTResolving, httpFetcher: any MTASTSHTTPFetching,
        addressResolver: (any MTASTSAddressResolving)? = nil,
        configuration: Configuration = .init(), now: @escaping @Sendable () -> Date
    ) {
        self.dnsResolver = dnsResolver
        self.httpFetcher = httpFetcher
        self.addressResolver = addressResolver
        self.configuration = configuration
        self.now = now
    }

    /// - Parameter domain: The destination domain (not the MX exchange
    ///   hostname) -- RFC 8461 §3.1's discovery/fetch hostnames
    ///   (`_mta-sts.<domain>`, `mta-sts.<domain>`) are both derived from the
    ///   recipient domain, never from a resolved MX hostname.
    public func policy(for domain: String) async -> MTASTSPolicy? {
        let currentTime = now()
        // Fast path: a still-valid cached policy is used directly, with no
        // discovery/fetch at all (plan §9 Phase 4's "cache... so you're not
        // fetching on every single send" requirement) -- this is the only
        // branch that guarantees zero calls to `dnsResolver`/`httpFetcher`,
        // *unless* FIX B's id-recheck cadence is due (see below), in which
        // case it costs at most one TXT lookup, never an HTTPS fetch.
        if let cached = cache[domain], cached.expiresAt > currentTime {
            let recheckDue = currentTime.timeIntervalSince(cached.lastIDCheckedAt) >= configuration.idRecheckInterval
            if !recheckDue {
                return cached.policy
            }
            // FIX B (protocol review): RFC 8461 §3.1 -- "senders need only
            // check the TXT record's version 'id' against the cached
            // value" -- and §3.3's suggested "once per day" cadence
            // (`configuration.idRecheckInterval`). A still-`max_age`-valid
            // cached policy is otherwise never re-verified at all until it
            // naturally expires, so a domain that republishes a policy
            // update (a fresh `id`) faster than its old policy's `max_age`
            // would not have that update picked up until the stale entry
            // expired on its own -- this closes that gap without checking
            // on every single call (which would defeat the point of
            // caching).
            switch await currentDiscoveryID(domain: domain) {
            case .some(let currentID) where currentID == cached.discoveryID:
                // Unchanged -- still the same policy, just note the fresh
                // verification so the next recheck isn't due for another
                // full `idRecheckInterval`.
                var refreshed = cached
                refreshed.lastIDCheckedAt = currentTime
                cache[domain] = refreshed
                return cached.policy
            case .some:
                // The id changed -- RFC 8461 §3.1's signal that an updated
                // policy is available. Treat exactly like a cache miss:
                // fall through to the full discovery/fetch/parse below
                // rather than continuing to serve the now-known-stale
                // cached policy body.
                break
            case .none:
                // The recheck itself was inconclusive (TXT lookup failed,
                // or the record is no longer exactly-one/syntactically
                // valid per FIX A's gate) -- a transient DNS blip
                // shouldn't discard a policy that's still genuinely
                // `max_age`-valid, so this falls back to the cached policy
                // exactly like a full-fetch failure would (see the `catch`
                // branch below), just without spending an HTTPS round-trip
                // to discover that nothing changed. `lastIDCheckedAt` is
                // still bumped so a persistently-failing recheck doesn't
                // retry every single call -- it retries once per
                // `idRecheckInterval`, same cadence as the success path.
                var refreshed = cached
                refreshed.lastIDCheckedAt = currentTime
                cache[domain] = refreshed
                return cached.policy
            }
        }

        do {
            let fetched = try await fetchAndParsePolicy(domain: domain)
            let expiresAt = currentTime.addingTimeInterval(fetched.policy.maxAge)
            insertIntoCache(domain: domain, fetched: fetched, expiresAt: expiresAt, fetchedAt: currentTime)
            return fetched.policy
        } catch {
            // FIX #2 (milestone architecture review, BLOCKING -- corrected
            // citation): RFC 8461 §3.3 (fetched and verified directly
            // against the published RFC text, not assumed), not a
            // nonexistent "§5.1 anti-flapping" rule (no such text exists
            // anywhere in RFC 8461):
            //
            //   "If a valid TXT record is found but no policy can be
            //   fetched via HTTPS (for any reason), and there is no valid
            //   (non-expired) previously cached policy, senders MUST
            //   continue with delivery as though the domain has not
            //   implemented MTA-STS. Conversely, if no 'live' policy can be
            //   discovered via DNS or fetched via HTTPS, but a valid
            //   (non-expired) policy exists in the sender's cache, the
            //   sender MUST apply that cached policy."
            //
            // The RFC's own fallback is explicitly gated on the cached
            // policy being "valid (non-expired)" -- not indefinitely stale.
            // This actor's cache-lookup fast path above already only ever
            // returns a policy while `expiresAt > currentTime` (i.e.,
            // genuinely non-expired) with zero network calls; this `catch`
            // branch is reached only once that's no longer true (the
            // policy's own `max_age` has elapsed and a refresh was
            // attempted). Falling back to the stale cached policy here
            // even briefly past its own expiry is a **local, explicit,
            // reviewed extension** beyond the RFC's literal text (bounded
            // by `configuration.staleCacheCeiling`, not indefinite) --
            // see that property's doc comment for the full reasoning and
            // why an unbounded version of this fallback is a real
            // availability bug: a domain that legitimately decommissions
            // MTA-STS (removes its `_mta-sts` TXT record and well-known
            // policy file, e.g. after a hosting/DNS migration) would
            // otherwise have this sender continue enforcing its old,
            // abandoned `enforce` policy forever, since a DNS discovery
            // failure is folded into the very same fallback path as an
            // HTTPS fetch failure. Past the ceiling, a fetch failure
            // reverts the domain to policy-less, exactly matching RFC
            // 8461 §3.3's literal "non-expired" gating -- no cached
            // `enforce`/`testing` constraint outlives its own `max_age`
            // by more than `staleCacheCeiling`.
            guard let cached = cache[domain] else { return nil }
            let staleSince = currentTime.timeIntervalSince(cached.expiresAt)
            guard staleSince <= configuration.staleCacheCeiling else {
                cache.removeValue(forKey: domain)
                return nil
            }
            return cached.policy
        }
    }

    /// FIX #4 (MEDIUM security, milestone security review): enforces
    /// `configuration.maxCacheEntries` on every cache write -- see that
    /// property's doc comment for the eviction policy (earliest
    /// `expiresAt` first) and rationale. A write that merely refreshes an
    /// already-cached domain never counts against the cap (it's not a new
    /// entry), so this only ever evicts when a genuinely new domain would
    /// push `cache.count` past the configured limit.
    private func insertIntoCache(domain: String, fetched: FetchedPolicy, expiresAt: Date, fetchedAt: Date) {
        if cache[domain] == nil, cache.count >= configuration.maxCacheEntries {
            if let oldestDomain = cache.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                cache.removeValue(forKey: oldestDomain)
            }
        }
        cache[domain] = CachedPolicy(
            policy: fetched.policy, expiresAt: expiresAt,
            discoveryID: fetched.discoveryID, lastIDCheckedAt: fetchedAt
        )
    }

    /// FIX A / FIX B (protocol review): RFC 8461 §3.1's discovery gate,
    /// factored out of `fetchAndParsePolicy(domain:)` so both a full fetch
    /// and a cheap `policy(for:)` id-only recheck enforce the exact same
    /// "exactly one, syntactically valid" rule and parse the `id` the same
    /// way -- there is exactly one place in this actor that decides
    /// whether a TXT lookup result counts as "a valid MTA-STS discovery
    /// record" at all.
    ///
    /// - Throws: `.noSTSv1DiscoveryRecord` if the TXT lookup itself
    ///   failed, returned anything other than exactly one record (RFC
    ///   8461 §3.1: "If the number of resulting records is not one ...
    ///   senders MUST assume the recipient domain does not have an
    ///   available MTA-STS Policy" -- fetched and verified directly
    ///   against the published RFC text), or that one record isn't a
    ///   syntactically valid `v=STSv1; ...; id=<token>; ...` string (the
    ///   same guard's "or if the resulting record is syntactically
    ///   invalid" clause -- a record with no `id` field at all is treated
    ///   as syntactically invalid here, since FIX B has no cached value to
    ///   compare against without one).
    private func discoverValidRecord(domain: String) async throws -> DiscoveryRecord {
        let discoveryRecords: [String]
        do {
            discoveryRecords = try await dnsResolver.resolveTXT(name: "_mta-sts.\(domain)")
        } catch {
            throw MTASTSDiscoveryError.noSTSv1DiscoveryRecord
        }
        guard discoveryRecords.count == 1, let record = discoveryRecords.first,
              let parsed = Self.parseDiscoveryRecord(record)
        else {
            throw MTASTSDiscoveryError.noSTSv1DiscoveryRecord
        }
        return parsed
    }

    /// Parses one `_mta-sts.<domain>` TXT record's `v=STSv1; id=<token>;
    /// ...` syntax (RFC 8461 §3.1) into a `DiscoveryRecord`, or `nil` if it
    /// isn't one -- the version tag isn't exactly `v=STSv1`, or there's no
    /// non-empty `id` field. Deliberately tolerant of the exact separator
    /// spacing the RFC's own examples vary on (`v=STSv1; id=...` vs.
    /// `v=STSv1;id=...`) by trimming whitespace around each `;`-delimited
    /// field, mirroring `MTASTSPolicyParser.parse(_:)`'s own
    /// defensive-but-not-loose tolerance for a real, untrusted DNS
    /// response.
    private static func parseDiscoveryRecord(_ record: String) -> DiscoveryRecord? {
        let fields = record.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let versionField = fields.first, versionField == "v=STSv1" else { return nil }
        for field in fields.dropFirst() {
            guard let equalsIndex = field.firstIndex(of: "=") else { continue }
            let key = field[field.startIndex..<equalsIndex].trimmingCharacters(in: .whitespaces)
            let value = field[field.index(after: equalsIndex)...].trimmingCharacters(in: .whitespaces)
            guard key == "id", !value.isEmpty else { continue }
            return DiscoveryRecord(id: value)
        }
        return nil
    }

    /// FIX B: the cheap half of the id-recheck -- just the discovery gate,
    /// with every failure mode (lookup error, ambiguous/invalid record)
    /// folded into `nil` rather than a thrown error, since `policy(for:)`'s
    /// recheck path treats "couldn't confirm" the same regardless of which
    /// specific thing went wrong (see that call site's own comment).
    private func currentDiscoveryID(domain: String) async -> String? {
        (try? await discoverValidRecord(domain: domain))?.id
    }

    /// Discovery (RFC 8461 §3.1) + FIX D's SSRF-class address pre-check +
    /// fetch (§3.2) + FIX C's response-size cap + parse, as one throwing
    /// operation -- any failure at any stage is folded into an
    /// `MTASTSDiscoveryError`, caught by `policy(for:)`'s caller above.
    private func fetchAndParsePolicy(domain: String) async throws -> FetchedPolicy {
        let record = try await discoverValidRecord(domain: domain)

        // RFC 8461 §3.2: always `https://mta-sts.<domain>/.well-known/mta-sts.txt`,
        // never derived from a resolved MX hostname or affected by any
        // caller-configured port.
        guard let url = URL(string: "https://mta-sts.\(domain)/.well-known/mta-sts.txt") else {
            throw MTASTSDiscoveryError.fetchFailed
        }

        // Address vetting. The default `NIOMTASTSHTTPFetcher` resolves the
        // policy host once, filters the addresses with
        // `DNSAddress.isRoutable` and dials a vetted one itself, so the
        // address checked is the address used. This optional pre-check is
        // for a custom `httpFetcher` that can't do that: with an
        // `addressResolver`, the fetch is refused when every address the
        // host resolves to is private or reserved (it can't stop that
        // fetcher from resolving differently afterwards).
        if let addressResolver, !configuration.allowPrivateAddresses {
            let resolvedAddresses: [DNSAddress]
            do {
                resolvedAddresses = try await addressResolver.resolveAddresses(hostname: url.host ?? "mta-sts.\(domain)")
            } catch {
                throw MTASTSDiscoveryError.fetchFailed
            }
            guard resolvedAddresses.contains(where: \.isRoutable) else {
                throw MTASTSDiscoveryError.addressFilteredAsPrivate
            }
        }

        let response: MTASTSHTTPResponse
        do {
            response = try await httpFetcher.fetch(url: url)
        } catch MTASTSHTTPFetchError.responseTooLarge {
            throw MTASTSDiscoveryError.responseTooLarge
        } catch MTASTSHTTPFetchError.noPermittedAddress {
            throw MTASTSDiscoveryError.addressFilteredAsPrivate
        } catch {
            throw MTASTSDiscoveryError.fetchFailed
        }
        guard response.statusCode == 200 else { throw MTASTSDiscoveryError.fetchFailed }
        guard let contentType = response.contentType,
              contentType.lowercased().hasPrefix("text/plain")
        else { throw MTASTSDiscoveryError.invalidContentType }
        // RFC 8461 §3.3 SHOULD, 64 KiB (see `maximumPolicyResponseSizeBytes`).
        // The default fetcher stops reading at the cap; this re-check covers
        // custom fetchers before anything is parsed or cached.
        guard response.body.count <= Self.maximumPolicyResponseSizeBytes else {
            throw MTASTSDiscoveryError.responseTooLarge
        }

        let text = String(decoding: response.body, as: UTF8.self)
        guard let policy = MTASTSPolicyParser.parse(text) else { throw MTASTSDiscoveryError.malformedPolicy }
        return FetchedPolicy(policy: policy, discoveryID: record.id)
    }
}

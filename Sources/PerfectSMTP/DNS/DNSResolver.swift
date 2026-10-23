//
//  DNSResolver.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3 ("the single largest engineering item in the whole
//  plan"): a hand-rolled MX/A/AAAA resolver over NIO UDP, since no official
//  SSWG DNS resolver package exists. This is the public surface
//  `DirectMXTransport` (a separate, later piece of work, not built here)
//  consumes -- see each method's doc comment for the exact contract.
//
//  Scope, deliberately narrow (plan's explicit instruction): MX/A/AAAA
//  resolution only. Not a general-purpose DNS client -- no arbitrary record
//  type queries, no zone transfers, no DNSSEC validation (plan §9 Phase 4
//  owns the MTA-STS/DANE trust-policy layer; a validating resolver is a
//  distinct, larger concern explicitly flagged there as a likely
//  scope-narrowing candidate, not something this piece builds). Not the
//  retry-queue/circuit-breaker/multi-host-pool machinery either -- that is
//  `DirectMXTransport`'s job, built on top of what this file returns.
//
//  Query mechanics (UDP with randomized ID + ephemeral source port, timeout
//  + bounded retry, TCP fallback on a truncated response) live in
//  `DNSTransport.swift`; wire encoding/decoding lives in
//  `DNSWireFormat.swift` (pure `[UInt8]`, independently unit-testable with
//  no network or NIO channel involved). This file is the MX-specific
//  business logic layered on top: preference ordering + equal-preference
//  randomization (RFC 5321 §5.1), null-MX hard-fail (RFC 7505), and bounded
//  CNAME-chain following for address resolution (RFC 2181 §10.3 discourages
//  an MX target resolving through a CNAME, but real-world zones do it often
//  enough to matter for actual delivery).
//

import Foundation
import NIOCore

/// Resolves MX and A/AAAA records for outbound mail delivery over a
/// hand-rolled RFC 1035 UDP/TCP DNS client. See the type's methods for the
/// exact contract each one guarantees; see the file header above for what
/// is deliberately out of scope.
public struct DNSResolver: Sendable {
    /// One MX record, preference-ordered per `resolveMX(domain:)`'s
    /// contract. `exchange` is the mail server hostname exactly as decoded
    /// from the wire (name-decompressed, no trailing dot) -- callers pass
    /// it to `resolveAddresses(hostname:)` to get connectable addresses.
    public struct MXRecord: Sendable, Hashable {
        public let preference: Int
        public let exchange: String

        public init(preference: Int, exchange: String) {
            self.preference = preference
            self.exchange = exchange
        }
    }

    /// Errors `DNSResolver`'s public methods throw. Every case is meant to
    /// be independently actionable by a caller building retry/circuit-
    /// breaker logic on top (`DirectMXTransport`'s job, not this type's) --
    /// none of them are a catch-all.
    public enum ResolveError: Error, Sendable, Equatable {
        /// RFC 7505: the domain published exactly one MX record,
        /// preference 0, exchange `"."` -- an explicit, authoritative
        /// declaration that the domain does not accept email at all.
        /// Distinct from `.noRecordsFound` (which just means "no MX
        /// records exist, try the RFC 5321 §5.1 implicit-MX fallback")
        /// specifically so a caller can hard-fail immediately here without
        /// ever attempting that fallback -- see `resolveMX(domain:)`'s doc
        /// comment for why this resolver doesn't attempt the fallback
        /// itself.
        case nullMX
        /// The response contained no records of the type being resolved
        /// (a "NODATA" response: NOERROR, empty answer section) or the
        /// name doesn't exist at all (NXDOMAIN). This resolver doesn't
        /// distinguish the two -- both mean "nothing usable came back,"
        /// which is what every caller actually needs to act on.
        case noRecordsFound
        /// No nameserver produced a valid, correctly-correlated response
        /// within `queryTimeout` across all configured retries.
        case timeout
        /// A response was received from the queried nameserver but failed
        /// to decode as a well-formed DNS message (see `DNSWireError` for
        /// the specific wire-format violation) -- a distinct case from
        /// `.timeout` because it indicates a genuinely malformed reply from
        /// the server actually queried, not silence.
        case malformedResponse
        /// The nameserver returned a non-{NOERROR, NXDOMAIN} RCODE (RFC
        /// 1035 §4.1.1) -- e.g. `2` (SERVFAIL) or `5` (REFUSED).
        case serverFailure(rcode: Int)
        /// A CNAME chain being followed while resolving an address either
        /// revisited a name it had already followed (a genuine cycle) or
        /// exceeded `DNSResolver.maximumCNAMEHops` hops without reaching a
        /// terminal A/AAAA record. Both are the same practical outcome --
        /// "this chain can't be safely followed to completion" -- so they
        /// share one case rather than needing the caller to distinguish
        /// "a real loop" from "just unusually/maliciously long."
        case cnameLoop
        /// `nameservers` was empty (either explicitly passed as `[]`, or
        /// system discovery + the hardcoded fallback both somehow produced
        /// nothing -- see `systemNameservers()`, this should not happen in
        /// practice since the fallback list is always non-empty).
        case noNameserversConfigured
    }

    /// The nameservers queried, in order, for every lookup. See
    /// `systemNameservers()` for the default discovery/fallback behavior.
    public let nameservers: [SocketAddress]
    let group: any EventLoopGroup
    /// Applied per UDP attempt and per TCP fallback attempt (not a single
    /// budget for the whole multi-nameserver, multi-retry lookup) -- see
    /// `DNSTransport.swift`'s query loop for exactly how attempts are
    /// sequenced within this.
    public let queryTimeout: TimeAmount

    /// Bound on CNAME hops followed while resolving one hostname's
    /// addresses (`resolveAddresses(hostname:)`) -- both the "chase a
    /// CNAME chain across multiple queries" case and, transitively, the
    /// defense against a CNAME cycle. 8 is generous headroom over any
    /// legitimate chain (RFC 2181 §10.3 actively discourages MX targets
    /// resolving through even *one* CNAME) while still being a hard,
    /// small bound.
    static let maximumCNAMEHops = 8

    /// - Parameters:
    ///   - nameservers: Servers queried, in order, for every lookup.
    ///     Defaults to `systemNameservers()` (see that method for the
    ///     `/etc/resolv.conf`-then-hardcoded-fallback behavior it
    ///     documents). Explicit and overridable specifically so callers
    ///     (and this package's own tests) aren't forced to depend on
    ///     either path -- pass a test-local fake server's address here.
    ///   - group: The `EventLoopGroup` UDP/TCP query channels are bootstrapped
    ///     on. Not retained beyond each individual query -- see
    ///     `DNSTransport.swift`'s doc comment for why this resolver dials a
    ///     fresh channel per query rather than pooling, unlike
    ///     `SMTPConnectionPool`.
    ///   - queryTimeout: Per-attempt timeout (UDP or TCP), default 5s.
    public init(
        nameservers: [SocketAddress] = DNSResolver.systemNameservers(),
        group: any EventLoopGroup,
        queryTimeout: TimeAmount = .seconds(5)
    ) {
        self.nameservers = nameservers
        self.group = group
        self.queryTimeout = queryTimeout
    }

    // MARK: - Public API

    /// Resolves MX records for `domain`, sorted per RFC 5321 §5.1: ascending
    /// preference, with equal-preference records shuffled (a fresh random
    /// order on every call) so callers who try hosts in the returned order
    /// distribute load across equally-preferred exchanges rather than
    /// always hammering the first one listed.
    ///
    /// - Throws: `.nullMX` (RFC 7505) if the domain published exactly one
    ///   `preference=0, exchange="."` record -- callers must hard-fail on
    ///   this, never fall through to an address lookup.
    ///
    ///   `.noRecordsFound` if there are no MX records at all (NODATA or
    ///   NXDOMAIN). **This resolver deliberately does not attempt the RFC
    ///   5321 §5.1 implicit-MX fallback** ("if no MX records exist, but the
    ///   domain itself has an A/AAAA record, treat that as an implicit MX")
    ///   itself -- that decision is left to the caller
    ///   (`DirectMXTransport`). Rationale: (1) it keeps this method's
    ///   contract narrow and single-purpose ("resolve MX records, nothing
    ///   else"), matching every other method here; (2) whether to even
    ///   *attempt* the fallback plausibly depends on transport-layer state
    ///   this resolver has no visibility into (e.g. a circuit breaker
    ///   already open for `domain` itself); (3) the public API already
    ///   hands the caller both primitives it needs to implement the
    ///   fallback in exactly one extra call: `.noRecordsFound` from this
    ///   method, then `resolveAddresses(hostname: domain)`. Judgment call --
    ///   flagged explicitly per this task's instructions since it's the one
    ///   sketch line that named a real design choice to make.
    public func resolveMX(domain: String) async throws -> [MXRecord] {
        let message = try await query(name: domain, type: .mx)
        return try Self.processMXAnswers(Self.answers(in: message, for: domain))
    }

    /// Resolves both A and AAAA records for `hostname`, following CNAME
    /// chains as needed (RFC 2181 §10.3; bounded by
    /// `maximumCNAMEHops`, cycle-guarded -- see `resolveAddressesOfType`).
    /// Both address families are queried and returned together;
    /// **IPv4/IPv6 preference ordering at connect time is the transport
    /// layer's decision, not this resolver's** -- addresses are returned in
    /// whatever order the two independent lookups happen to complete in,
    /// which callers must not treat as meaningful.
    ///
    /// A record found for one family and not the other is not an error --
    /// e.g. an AAAA-less host returns just its A addresses. Only throws if
    /// *neither* family produced anything.
    ///
    /// - Throws: `.noRecordsFound` if both families are empty.
    ///   `.cnameLoop` if a family's CNAME chain couldn't be safely
    ///   followed (see that case's doc comment) -- but only when it's the
    ///   *only* thing this call has to report; if the other family
    ///   resolved successfully, that success is returned and the other
    ///   family's failure is silently dropped (documented simplification --
    ///   see `resolveAddresses`'s implementation comment for the trade-off).
    public func resolveAddresses(hostname: String) async throws -> [DNSAddress] {
        async let aResult = Self.capture { try await self.resolveAddressesOfType(.a, name: hostname) }
        async let aaaaResult = Self.capture { try await self.resolveAddressesOfType(.aaaa, name: hostname) }
        let results = [await aResult, await aaaaResult]
        let combined = results.flatMap { (try? $0.get()) ?? [] }
        if !combined.isEmpty { return combined }
        // Release review: neither family produced an address. Report why,
        // rather than collapsing every failure into `.noRecordsFound`: a
        // timeout or SERVFAIL is temporary (the caller should retry), while
        // NODATA/NXDOMAIN in both families is a real "no such host".
        let failures: [ResolveError] = results.compactMap {
            if case .failure(let error) = $0 { return error }
            return nil
        }
        if let transient = failures.first(where: \.isTransient) { throw transient }
        if let other = failures.first(where: { $0 != .noRecordsFound }) { throw other }
        throw ResolveError.noRecordsFound
    }

    /// Runs `operation`, mapping any non-`ResolveError` failure (a socket
    /// error, say) to `.timeout`: from the caller's side both mean the
    /// nameservers couldn't be reached.
    private static func capture(_ operation: @Sendable () async throws -> [DNSAddress]) async -> Result<[DNSAddress], ResolveError> {
        do {
            return .success(try await operation())
        } catch let error as ResolveError {
            return .failure(error)
        } catch {
            return .failure(.timeout)
        }
    }

    /// Resolves TXT records for `name`, returning one `String` per resource
    /// record found -- each record's `<character-string>`s concatenated
    /// (RFC 8461's `v=STSv1; id=...` value is conventionally emitted as a
    /// single `<character-string>` in practice, but concatenating rather
    /// than taking only the first is the safer, more conservative reading
    /// for the rare record split across more than one). Added for plan §9
    /// Phase 4 (MTA-STS discovery, RFC 8461 §3.1) -- deliberately narrow,
    /// matching this resolver's existing scope discipline: no attempt at a
    /// general-purpose TXT API (SPF/DKIM-style multi-value parsing, record
    /// selection heuristics, etc.), just "give me every TXT string this
    /// name publishes" and let the caller (`MTASTSPolicyManager`) decide
    /// what to do with it.
    ///
    /// - Throws: `.noRecordsFound` if there are no TXT records at all
    ///   (NODATA or NXDOMAIN) -- the normal, expected outcome for the
    ///   overwhelming majority of domains, which don't publish an
    ///   `_mta-sts.<domain>` TXT record at all. Every other error case is
    ///   shared with `resolveMX`/`resolveAddresses` (see those doc
    ///   comments) since the underlying query mechanics are identical.
    public func resolveTXT(name: String) async throws -> [String] {
        let message = try await query(name: name, type: .txt)
        try Self.validateResponseCode(message)
        let strings: [String] = Self.answers(in: message, for: name).compactMap { record in
            guard case .txt(let parts) = record.rdata else { return nil }
            return parts.joined()
        }
        guard !strings.isEmpty else { throw ResolveError.noRecordsFound }
        return strings
    }

    // MARK: - MX processing (pure, unit-tested directly against hand-built records)

    /// Converts a decoded answer section's MX records into the sorted,
    /// equal-preference-shuffled list `resolveMX(domain:)` returns, or
    /// throws `.nullMX`/`.noRecordsFound` per that method's contract. Pure
    /// and free of any network/NIO dependency specifically so it can be
    /// unit-tested against hand-built `DNSResourceRecord` values without a
    /// live resolver or wire bytes at all.
    static func processMXAnswers(_ answers: [DNSResourceRecord]) throws -> [MXRecord] {
        var entries: [(preference: UInt16, exchange: String)] = answers.compactMap {
            guard case .mx(let preference, let exchange) = $0.rdata else { return nil }
            return (preference, exchange)
        }
        guard !entries.isEmpty else { throw ResolveError.noRecordsFound }

        // RFC 7505 §3: a domain that publishes a null MX "MUST NOT
        // advertise any other MX RR", and §4 has senders treat it as "this
        // domain accepts no mail". The RFC doesn't spell out a mixed RRset,
        // so any null MX in the set wins: falling through to the other
        // records would deliver mail the domain owner said to refuse.
        if entries.contains(where: { $0.preference == 0 && isRootDomain($0.exchange) }) {
            throw ResolveError.nullMX
        }
        // Release review: only LDH host names are usable exchanges. A
        // root exchange at another preference, or a name with a byte that
        // made it through DNS decoding but isn't a host name, is dropped;
        // if nothing usable is left the response is malformed rather than
        // "no MX" (which would trigger the implicit-MX fallback).
        entries.removeAll { !AddressSyntax.isHostname($0.exchange) }
        guard !entries.isEmpty else { throw ResolveError.malformedResponse }

        let grouped = Dictionary(grouping: entries, by: { $0.preference })
        return grouped.keys.sorted().flatMap { preference in
            // `.shuffled()` re-randomizes on every call -- this is what
            // gives equal-preference records their RFC 5321 §5.1
            // load-distribution property; see
            // `DNSResolverMXOrderingTests` for the statistical regression
            // guarding against a future change accidentally making this
            // deterministic (e.g. swapping in a stable sort).
            grouped[preference]!.shuffled().map { MXRecord(preference: Int($0.preference), exchange: $0.exchange) }
        }
    }

    /// RFC 7505's null-MX exchange is the DNS root, which this codec
    /// decodes as the empty string (a zero-length root label has no labels
    /// to join) -- `"."` is accepted too in case a caller or fixture
    /// constructs a `DNSResourceRecord` by hand with the more conventional
    /// textual root representation.
    private static func isRootDomain(_ name: String) -> Bool {
        name.isEmpty || name == "."
    }

    // MARK: - Address resolution / CNAME following

    /// Not `private` (plain `internal`) specifically so
    /// `DNSResolverCNAMEFollowingTests` can exercise the CNAME-chain/cycle
    /// logic directly against a local fake server and assert the precise
    /// `.cnameLoop` error -- `resolveAddresses(hostname:)`'s public
    /// A+AAAA-combining wrapper deliberately swallows this into
    /// `.noRecordsFound` when the other family also fails (see that
    /// method's doc comment), which would make a loop-guard regression
    /// impossible to assert precisely through the public API alone.
    func resolveAddressesOfType(_ type: DNSRecordType, name: String) async throws -> [DNSAddress] {
        var currentName = name
        var visited = Set<String>()
        for _ in 0..<Self.maximumCNAMEHops {
            let key = currentName.lowercased()
            guard visited.insert(key).inserted else { throw ResolveError.cnameLoop }

            let message = try await query(name: currentName, type: type)
            try Self.validateResponseCode(message)

            let (addresses, cnameTarget) = Self.extractAddresses(from: message, type: type, name: currentName)
            if !addresses.isEmpty { return addresses }
            guard let cnameTarget else { return [] } // NODATA: name exists, no record of this type, no CNAME either
            guard AddressSyntax.isHostname(cnameTarget) else { throw ResolveError.malformedResponse }
            currentName = cnameTarget
        }
        throw ResolveError.cnameLoop
    }

    /// Pulls every address record of `type` out of `message`'s answer
    /// section, plus the most recent CNAME target seen (the chain's next
    /// hop) if no terminal address record for `type` was present. Pure --
    /// unit-tested directly against hand-built `DNSMessage` values.
    static func extractAddresses(from message: DNSMessage, type: DNSRecordType) -> (addresses: [DNSAddress], cnameTarget: String?) {
        extractAddresses(from: message, type: type, name: message.questions.first?.name ?? "")
    }

    /// Release review: only records owned by `name`, or by the end of a
    /// CNAME chain starting at `name` within this same answer section, are
    /// used. A response that also carries `127.0.0.1` for some other owner
    /// name no longer contributes it.
    static func extractAddresses(from message: DNSMessage, type: DNSRecordType, name: String) -> (addresses: [DNSAddress], cnameTarget: String?) {
        let owner = chainEnd(in: message.answers, from: name)
        var addresses: [DNSAddress] = []
        for record in message.answers where sameName(record.name, owner) {
            switch record.rdata {
            case .a(let address) where type == .a: addresses.append(address)
            case .aaaa(let address) where type == .aaaa: addresses.append(address)
            default: break
            }
        }
        if !addresses.isEmpty { return (addresses, nil) }
        return ([], sameName(owner, name) ? nil : owner)
    }

    /// The answer records that belong to `name`: owned by it, or by the end
    /// of the CNAME chain that starts at it.
    static func answers(in message: DNSMessage, for name: String) -> [DNSResourceRecord] {
        let owner = chainEnd(in: message.answers, from: name)
        return message.answers.filter { sameName($0.name, owner) }
    }

    /// Follows CNAME records in `answers` from `name`, at most
    /// `maximumCNAMEHops` times, and returns where the chain ends.
    private static func chainEnd(in answers: [DNSResourceRecord], from name: String) -> String {
        var current = name
        var visited: Set<String> = [canonical(name)]
        for _ in 0..<maximumCNAMEHops {
            guard let next = answers.lazy.compactMap({ record -> String? in
                guard sameName(record.name, current), case .cname(let target) = record.rdata else { return nil }
                return target
            }).first, visited.insert(canonical(next)).inserted else { break }
            current = next
        }
        return current
    }

    /// DNS names compare case-insensitively (ASCII only) and ignore a
    /// trailing root dot.
    static func sameName(_ a: String, _ b: String) -> Bool {
        canonical(a) == canonical(b)
    }

    private static func canonical(_ name: String) -> String {
        (name.hasSuffix(".") ? String(name.dropLast()) : name).lowercased()
    }

    // MARK: - Response-code classification

    static func validateResponseCode(_ message: DNSMessage) throws {
        switch message.header.responseCode {
        case 0, 3: return // NOERROR, NXDOMAIN -- both handled via an empty answer section, not here
        default: throw ResolveError.serverFailure(rcode: Int(message.header.responseCode))
        }
    }

    // MARK: - System nameserver discovery (plan §9 Phase 3, point 5)

    /// Best-effort system nameserver discovery: parses `/etc/resolv.conf`
    /// (present on both macOS and Linux, even though macOS's actual
    /// primary resolution path since 10.4 is `mDNSResponder`/System
    /// Configuration, not this file directly -- `/etc/resolv.conf` is
    /// still populated and readable on macOS and is the only
    /// dependency-free source this resolver can reasonably parse itself)
    /// for `nameserver <ip>` lines. Falls back to a small hardcoded list of
    /// well-known public resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`)
    /// if the file is missing, unreadable, or contains no usable
    /// `nameserver` lines.
    ///
    /// **This is a pragmatic default, not a robust general-purpose
    /// solution** -- it doesn't watch the file for changes, doesn't handle
    /// `search`/`domain`/`options` directives, and the hardcoded fallback
    /// is a real behavioral choice (querying a third party's public
    /// resolver rather than failing outright) that operators running in a
    /// restricted network may not want. `nameservers` is an explicit,
    /// overridable `init` parameter specifically so this default never has
    /// to be relied on by a caller (or this package's own tests) that
    /// needs different behavior.
    public static func systemNameservers() -> [SocketAddress] {
        if let parsed = try? parseResolvConf(path: "/etc/resolv.conf"), !parsed.isEmpty {
            return parsed
        }
        return fallbackNameservers
    }

    static let fallbackNameservers: [SocketAddress] = {
        ["1.1.1.1", "8.8.8.8"].compactMap { try? SocketAddress(ipAddress: $0, port: 53) }
    }()

    static func parseResolvConf(path: String) throws -> [SocketAddress] {
        let contents = try readFile(path)
        var result: [SocketAddress] = []
        for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingWhitespace()
            guard line.hasPrefix("nameserver") else { continue }
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 2, fields[0] == "nameserver" else { continue }
            guard let address = try? SocketAddress(ipAddress: String(fields[1]), port: 53) else { continue }
            result.append(address)
        }
        return result
    }

    /// Reads a whole small text file as UTF-8. Hand-rolled rather than
    /// pulling in `Foundation.String(contentsOfFile:)` -- `PerfectSMTP`
    /// (unlike `PerfectSMTPCore`) does already use `Foundation` elsewhere
    /// (`SMTPConnection.swift`'s `Data`/base64 use) so there'd be no new
    /// dependency either way, but a plain POSIX read keeps this file
    /// self-contained and avoids Foundation's file-reading error being
    /// harder to distinguish from "file doesn't exist" (which `parseResolvConf`'s
    /// caller treats as an expected, silent fall-through to the hardcoded
    /// fallback, not a surfaced error).
    private static func readFile(_ path: String) throws -> String {
        guard let fileHandle = fopen(path, "r") else { throw ResolveConfError.unreadable }
        defer { fclose(fileHandle) }
        var data: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let bytesRead = fread(&buffer, 1, buffer.count, fileHandle)
            guard bytesRead > 0 else { break }
            data.append(contentsOf: buffer[0..<bytesRead])
        }
        return String(decoding: data, as: UTF8.self)
    }

    private enum ResolveConfError: Error {
        case unreadable
    }

    // MARK: - Query dispatch (nameserver iteration, UDP retry, TCP fallback)

    /// Sends `(name, type)` to each configured nameserver in turn,
    /// retrying transient UDP loss per `DNSTransport`'s retry/backoff
    /// policy, transparently falling back to TCP when a response's `TC` bit
    /// is set. Returns the first successfully-decoded, correctly-correlated
    /// response with an acceptable RCODE (`validateResponseCode` above).
    func query(name: String, type: DNSRecordType) async throws -> DNSMessage {
        guard !nameservers.isEmpty else { throw ResolveError.noNameserversConfigured }
        return try await DNSTransport.query(name: name, type: type, resolver: self)
    }
}

extension DNSResolver.ResolveError {
    /// Whether retrying later could succeed: no answer in time, a SERVFAIL
    /// or other failure RCODE, an unparseable reply, or no nameserver.
    /// NODATA/NXDOMAIN, null MX and CNAME loops are answers, not failures
    /// to get one.
    public var isTransient: Bool {
        switch self {
        case .timeout, .serverFailure, .malformedResponse, .noNameserversConfigured: return true
        case .nullMX, .noRecordsFound, .cnameLoop: return false
        }
    }
}

/// A minimal `String.trimmingCharacters(in: .whitespaces)` equivalent that
/// doesn't require `Foundation.CharacterSet` -- used only by
/// `DNSResolver.parseResolvConf`'s line trimming.
extension Substring {
    func trimmingWhitespace() -> Substring {
        var slice = self
        while let first = slice.first, first == " " || first == "\t" || first == "\r" { slice = slice.dropFirst() }
        while let last = slice.last, last == " " || last == "\t" || last == "\r" { slice = slice.dropLast() }
        return slice
    }
}

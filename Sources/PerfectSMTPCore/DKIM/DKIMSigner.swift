//
//  DKIMSigner.swift
//  PerfectSMTPCore
//
//  RFC 6376 (DKIM) + RFC 8463 (Ed25519-SHA256) signer -- see
//  Documentation/swift6-nio-rewrite-plan.md §4.6, this file's primary
//  spec, including the corrected oversigning-of-absent-headers semantics
//  (RFC 6376 §5.4/§8.15) and the RSA-2048 minimum.
//
//  Sendability note (plan §4.6's flagged open question -- "must be
//  verified before committing DKIMSigner to a plain Sendable struct"):
//  RESOLVED. Both `_RSA.Signing.PrivateKey` and `Curve25519.Signing.
//  PrivateKey` are confirmed genuinely `Sendable` (not `@unchecked`) in
//  the pinned swift-crypto 4.5.1, verified directly against the resolved
//  package source rather than assumed:
//    .build/checkouts/swift-crypto/Sources/CryptoExtras/RSA/RSA.swift:158
//      `public struct PrivateKey: Sendable { private var backing:
//      BackingPrivateKey ... }` -- unconditional `Sendable`, no
//      `@unchecked`.
//    .build/checkouts/swift-crypto/Sources/Crypto/Keys/EC/Ed25519Keys.swift:50
//      `public struct PrivateKey: ECPrivateKey, Sendable`.
//  So `DKIMSigner` is a plain `Sendable struct` holding key material
//  directly -- no actor or Sendable-box wrapper needed, the plan's
//  fallback path is not taken.
//
//  Placement/ordering invariant (plan §4.6, confirmed by the protocol
//  review, not re-litigated here): `sign(_:)` is the last transformation
//  before `SMTPMailer.composeAndSign` serializes the result into
//  `SignedMessage` -- nothing downstream re-encodes headers or body.
//  Wire-level dot-stuffing is applied later still, by the transport's DATA
//  writer (`SMTPConnection.sendBodyAndFinalize` -> `DotStuffing.encode`),
//  over these exact already-signed bytes; that's signature-preserving
//  because DKIM canonicalization operates on the logical message and
//  dot-stuffing is a wire-transparency mechanism the receiver reverses
//  before verification -- genuinely orthogonal, not a hazard, precisely
//  because nothing between here and the wire touches header or body bytes
//  again.
//

import Crypto
import Foundation
import _CryptoExtras

public struct DKIMSigner: Sendable, MessageSigner {
    public enum Algorithm: Sendable {
        case rsaSHA256
        case ed25519SHA256

        var tagValue: String {
            switch self {
            case .rsaSHA256: return "rsa-sha256"
            case .ed25519SHA256: return "ed25519-sha256"
            }
        }
    }

    public enum ConfigurationError: Error, Sendable, Equatable {
        /// A signer needs at least one key to sign with.
        case noSigningKeys
        /// RFC 6376 §3.3.3 / plan §4.6: RSA-SHA256 keys must be >=2048
        /// bits. `SigningKey.rsa(pem:)` already enforces this via
        /// swift-crypto's own `pemRepresentation:` initializer, but it's
        /// re-checked here too (defense in depth) since `SigningKey.rsa`
        /// is a public enum case a caller could in principle construct
        /// directly from a key parsed some other way, bypassing that
        /// convenience initializer entirely.
        case rsaKeyTooSmall(bits: Int)
        /// `domain` (the `d=` tag) isn't an LDH hostname.
        case invalidDomain(String)
        /// `selector` (the `s=` tag) isn't one or more LDH labels.
        case invalidSelector(String)
    }

    let domain: String
    let selector: String
    let signedHeaders: [String]
    let canon: (header: Mode, body: Mode)
    let keys: [SigningKey]
    private let now: @Sendable () -> Date

    // FIX #3 (milestone review, security pass): `DKIMSigner` deliberately
    // does *not* get its own `CustomStringConvertible` override. Swift's
    // default, reflection-based description for a struct that doesn't
    // conform recurses into each stored property's own description when
    // that property's type conforms to `CustomStringConvertible` --
    // `keys: [SigningKey]` now does (see `SigningKey`'s redacted
    // `description` in SigningKey.swift), so `"\(dkimSigner)"` already
    // prints `SigningKey(algorithm: rsa, <redacted>)` for each key element
    // rather than any key material, with no separate override needed here.

    /// Header names that are *always* oversigned by count+1 -- RFC 6376
    /// §5.4/§8.15 semantics, including a count of zero (plan §4.6's
    /// required correction: a header with zero real occurrences still
    /// gets exactly one `h=` entry, so that if an attacker later injects
    /// that header -- e.g. adds a `Bcc:` or a second `From:` -- its
    /// presence breaks the signature). This is the plan's explicit
    /// minimum set; callers cannot opt individual names out of it via
    /// `signedHeaders` -- only add to it.
    ///
    /// `bcc` is a deliberate addition beyond the plan's literal §4.6 list
    /// (`From`, `Subject`, `To`, `Cc`, `Date`, `Reply-To`, `Sender`,
    /// `Content-Type`, `MIME-Version`) -- that same section's own
    /// illustrative example of the injection this exists to prevent is
    /// "an attacker later injects that header (e.g. adds a `Bcc:` ...)",
    /// and this codebase's own Bug #1 (the historic Bcc-header-leak,
    /// fixed structurally in Phase 0 by `EmailMessage` never having a
    /// `bcc` field and `MIMEComposer`'s denylist rejecting one via
    /// `extraHeaders`) makes `Bcc:` a thematically central header for
    /// this specific library to defend. Since a legitimately-composed
    /// message here can never actually contain a `Bcc:` header, oversigning
    /// it costs exactly one guaranteed-phantom `h=` entry, always -- there
    /// is no present-header case to worry about, only the free defensive
    /// win.
    ///
    /// `list-unsubscribe`/`list-unsubscribe-post` are a Phase 5 addition
    /// (milestone review, two independent passes -- architecture and
    /// protocol). The architecture review applies the same `bcc` rationale
    /// above to these: a header this library can normally never emit
    /// without the caller explicitly setting `EmailMessage.listUnsubscribe`
    /// is exactly the "guaranteed-phantom, free defensive win" shape. The
    /// protocol review adds the specific RFC citation -- RFC 8058 §4:
    /// these headers "MUST be covered by the [DKIM] signature ... If the
    /// message does not have the required DKIM signature [covering these
    /// headers], the mail receiver SHOULD NOT offer a one-click
    /// unsubscribe for that message." Without this addition, a caller who
    /// enables both DKIM signing and `postOneClick` but forgets to also
    /// list these names in their own `signedHeaders` gets a message that
    /// composes fine and verifies fine, but silently fails Gmail/Yahoo's
    /// actual one-click eligibility check. `Precedence`/`Auto-Submitted`
    /// are deliberately NOT added here -- they're lower-stakes
    /// informational headers with no RFC 8058-style DKIM-coverage
    /// requirement, so the "oversign anything the composer might emit"
    /// argument is weaker for them than for the two names actually added.
    public static let alwaysOversignedHeaders: [String] = [
        "from", "subject", "to", "cc", "bcc", "date", "reply-to", "sender", "content-type", "mime-version",
        "list-unsubscribe", "list-unsubscribe-post",
    ]

    /// - Parameters:
    ///   - signedHeaders: The caller's base set of headers to sign, each
    ///     included once per its actual occurrence in the message (0 if
    ///     genuinely absent -- such names are simply omitted, since only
    ///     `alwaysOversignedHeaders` gets the defensive "count+1,
    ///     including zero" treatment). Names in `alwaysOversignedHeaders`
    ///     do not need to be repeated here; they're always covered.
    ///   - canon: Header/body canonicalization modes (RFC 6376 §3.4).
    ///     Default `(.relaxed, .relaxed)` per plan §4.6.
    ///   - keys: One key for single-algorithm signing, or two -- one
    ///     `.rsa`, one `.ed25519` -- to emit two `DKIM-Signature` headers
    ///     (dual-sign). Must be non-empty.
    ///   - now: Injectable clock for the `t=` (signing time) tag --
    ///     defaults to the wall clock; overridden by tests that need a
    ///     deterministic timestamp (e.g. to reproduce a fixed real-world
    ///     vector byte-for-byte).
    public init(
        domain: String,
        selector: String,
        signedHeaders: [String],
        canon: (header: Mode, body: Mode) = (.relaxed, .relaxed),
        keys: [SigningKey],
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        guard !keys.isEmpty else { throw ConfigurationError.noSigningKeys }
        for key in keys {
            if case .rsa(let privateKey) = key, privateKey.keySizeInBits < 2048 {
                throw ConfigurationError.rsaKeyTooSmall(bits: privateKey.keySizeInBits)
            }
        }
        // FIX #2 (milestone review, security pass): `domain`/`selector` are
        // interpolated directly into the `DKIM-Signature` header value
        // (`sign(_:)` below) with no further sanitization. They're trusted
        // operator config today, not remotely-attacker-controlled, but if a
        // future caller sources these from per-tenant/admin-console config
        // an embedded CR/LF would corrupt the header's own tag syntax --
        // reusing `HeaderEncoder.rejectHeaderInjection` (the same
        // fail-loud, uniformly-applied discipline every other
        // caller-controlled string embedded raw into a header or SMTP
        // command line already routes through) closes that off at
        // construction time rather than at the point of use.
        self.domain = try HeaderEncoder.rejectHeaderInjection(domain, field: "domain")
        self.selector = try HeaderEncoder.rejectHeaderInjection(selector, field: "selector")
        // RFC 6376 §3.5: `d=` is a domain name and `s=` a sequence of
        // sub-domains; both end up in a DNS query (`s._domainkey.d`).
        guard AddressSyntax.isHostname(domain) else { throw ConfigurationError.invalidDomain(domain) }
        guard AddressSyntax.isHostname(selector) else { throw ConfigurationError.invalidSelector(selector) }
        self.signedHeaders = signedHeaders
        self.canon = canon
        self.keys = keys
        self.now = now
    }

    /// Trusted, non-throwing designated init used only by
    /// `signingAdditionalHeaders(_:)` below to cheaply rebuild a copy of
    /// an already-validated signer with a different `signedHeaders` list.
    /// `domain`/`selector`/`keys` are taken verbatim from a signer that
    /// already passed the throwing `init`'s validation, so re-validating
    /// them here would be redundant, not protective -- this is a plain
    /// value copy, not a new trust boundary. The unused `trusted` label
    /// exists only to give this initializer a distinct signature from the
    /// public throwing one above (Swift resolves overloads by parameter
    /// list, not by `throws`).
    private init(
        domain: String,
        selector: String,
        signedHeaders: [String],
        canon: (header: Mode, body: Mode),
        keys: [SigningKey],
        now: @escaping @Sendable () -> Date,
        trusted: Void
    ) {
        self.domain = domain
        self.selector = selector
        self.signedHeaders = signedHeaders
        self.canon = canon
        self.keys = keys
        self.now = now
    }

    /// Returns a copy of this signer whose `signedHeaders` base set also
    /// includes `additionalHeaderNames` -- milestone review finding
    /// (LassoPerfectSMTP Phase F, protocol pass): `signedHeaders` is fixed
    /// at construction time, but `-extraMIMEHeaders`-style custom header
    /// names are a *per-message* concern (different messages may add
    /// different custom header names), so a signer built once at server
    /// startup with a static `signedHeaders: []` can never cover them --
    /// they'd be present in the composed message but absent from `h=`,
    /// giving an on-path party a way to tamper with a custom header
    /// without invalidating the signature.
    ///
    /// Cheap to call once per outgoing message: reconstructing a
    /// `DKIMSigner` does no cryptographic work at all -- `domain`/
    /// `selector`/`keys` are copied verbatim (no re-validation, see the
    /// trusted init above), so this is just an array copy plus a few
    /// `Sendable` closure/struct copies, nothing that scales with key size
    /// or message count. Safe for a caller (e.g. `SMTPMailer.composeAndSign`)
    /// to call unconditionally before every `sign(_:)`.
    public func signingAdditionalHeaders(_ additionalHeaderNames: [String]) -> DKIMSigner {
        guard !additionalHeaderNames.isEmpty else { return self }
        return DKIMSigner(
            domain: domain,
            selector: selector,
            signedHeaders: signedHeaders + additionalHeaderNames,
            canon: canon,
            keys: keys,
            now: now,
            trusted: ()
        )
    }

    /// Conforms `DKIMSigner` to `PerfectSMTPCore/MessageSigner.swift`'s
    /// seam -- the Phase 1 protocol `SMTPMailer` is already built against.
    /// Computes and prepends one `DKIM-Signature` header per configured
    /// key (dual RSA+Ed25519 signing prepends two, each computed
    /// independently over the same original headers -- neither signature
    /// signs the other's DKIM-Signature header).
    public func sign(_ message: RFC5322Message) throws -> RFC5322Message {
        let bodyCanon = DKIMCanonicalization.canonicalizeBody(message.body, mode: canon.body)
        let bh = Data(SHA256.hash(data: Data(bodyCanon))).base64EncodedString()

        let hNames = Self.effectiveHeaderNames(signedHeaders: signedHeaders, actualHeaders: message.headers)
        let hTagValue = hNames.joined(separator: ":")
        let timestamp = Int(now().timeIntervalSince1970)

        var dkimHeaders: [(name: String, value: String)] = []
        for key in keys {
            // FIX #4 (milestone review, DKIM/RFC-protocol expert pass):
            // `q=` and `i=` are both RFC 6376 §3.5 OPTIONAL tags,
            // deliberately omitted here, not forgotten. `q=` defaults to
            // `dns/txt`, the only query method ever used in practice --  an
            // explicit tag would be redundant. `i=` (the Agent or User
            // Identifier) is essentially unused outside third-party-signer
            // / ADSP-era configurations this signer doesn't target.
            let tagPrefix = "v=1; a=\(key.algorithm.tagValue); c=\(canon.header.rawValue)/\(canon.body.rawValue); " +
                "d=\(domain); s=\(selector); t=\(timestamp); h=\(hTagValue); bh=\(bh); b="
            let hashInput = DKIMSigningInput.headerHashInput(
                actualHeaders: message.headers,
                hNames: hNames,
                headerMode: canon.header,
                dkimSignatureHeaderValue: tagPrefix
            )
            let signatureBase64 = try key.sign(hashInput)
            dkimHeaders.append(("DKIM-Signature", tagPrefix + signatureBase64))
        }

        return RFC5322Message(headers: dkimHeaders + message.headers, body: message.body)
    }

    /// DMARC-alignment lint (plan §4.6): exposed as a pure data check, no
    /// logging dependency -- `PerfectSMTPCore` stays Foundation(+Crypto)-
    /// only. `SMTPMailer` (in the NIO target, which already depends on
    /// swift-log) type-checks its configured signer against `DKIMSigner`
    /// and logs a warning here when this returns `false`, right after
    /// `composeAndSign`; this check itself never blocks signing or
    /// sending -- misalignment is sometimes intentional (e.g. third-party
    /// sending infrastructure), so it can only ever produce a caller-
    /// visible warning, never a thrown error.
    ///
    /// Implements RFC 7489's "relaxed" DMARC alignment mode: `d=` need not
    /// equal the `From:` domain exactly, only share the same Organizational
    /// Domain -- checked here as a symmetric suffix relationship in either
    /// direction (`d=` a suffix of the `From:` domain, or vice versa). True
    /// Organizational-Domain determination needs a Public Suffix List,
    /// which this Foundation-only package deliberately does not bundle
    /// (see the milestone report for this documented limitation). Two real
    /// caveats follow from that, both confirmed by hand-computation against
    /// RFC 7489 §3.1.1 and fixed by a milestone review finding:
    ///
    /// 1. The relationship must be checked in **both** directions, not just
    ///    "`from` is a descendant of `d`". A standard ESP/bulk-sender
    ///    subdomain-signing config -- `d=bounces.example.com` (or
    ///    `mail.example.com`) signing `From: user@example.com` -- has both
    ///    domains reducing to the same Organizational Domain
    ///    (`example.com`) and RFC 7489 says they *should* align, but a
    ///    one-directional check reports this as misaligned (a false
    ///    negative on a common, legitimate pattern).
    /// 2. `d=` must not be permitted to be a bare public suffix. RFC 7489
    ///    §3.1.1 itself names this case: "a DKIM signature bearing a value
    ///    of 'd=com' would never allow an 'in alignment' result, as 'com'
    ///    should appear on all public suffix lists ... and therefore cannot
    ///    be an Organizational Domain." Without a real PSL, this is guarded
    ///    with `barePublicSuffixDenylist` below -- a short, explicitly
    ///    non-exhaustive list of common bare eTLDs/public suffixes, not
    ///    full PSL compliance. Anything not on that list (e.g. a genuine
    ///    two-label registrable domain like `example.com`) is still treated
    ///    as a valid Organizational Domain by this heuristic, matching the
    ///    documented limitation above: for the common case (registrable
    ///    domain used directly as `d=`) the heuristic is correct.
    public func isAligned(withFromDomain fromAddress: String) -> Bool {
        guard let fromDomain = Self.domain(fromAddress: fromAddress)?.lowercased() else { return false }
        let d = domain.lowercased()
        guard !Self.barePublicSuffixDenylist.contains(d) else { return false }
        if d == fromDomain { return true }
        return fromDomain.hasSuffix("." + d) || d.hasSuffix("." + fromDomain)
    }

    /// Small, explicitly non-exhaustive denylist of known bare public
    /// suffixes / eTLDs -- enough to catch RFC 7489 §3.1.1's own named
    /// forbidden case (`d=com`) and its common multi-label cousins
    /// (`d=co.uk`, etc.) without pulling in a full Public Suffix List
    /// dependency (a limitation this package already accepts elsewhere --
    /// see `isAligned`'s doc comment above). Best-effort heuristic, not PSL
    /// compliance: a public suffix missing from this list will still be
    /// (incorrectly) treated as a valid Organizational Domain.
    private static let barePublicSuffixDenylist: Set<String> = [
        // Common bare gTLDs.
        "com", "net", "org", "edu", "gov", "mil", "info", "biz", "io",
        // Common multi-label public suffixes (ccTLD second-level).
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "co.nz", "co.za", "co.in",
        "com.br", "com.cn", "com.mx",
    ]

    private static func domain(fromAddress address: String) -> String? {
        guard let atIndex = address.lastIndex(of: "@") else { return nil }
        let domainPart = address[address.index(after: atIndex)...]
        return domainPart.isEmpty ? nil : String(domainPart)
    }

    // MARK: - Oversigning (plan §4.6's required correction)

    /// Builds the flattened, possibly-repeating `h=` name sequence:
    /// `signedHeaders` first (each name once, in the caller's order,
    /// case-insensitively de-duplicated), then any of
    /// `alwaysOversignedHeaders` the caller didn't already list, appended
    /// once each -- guaranteeing every always-oversigned name gets at
    /// least a base entry regardless of whether the caller remembered to
    /// include it explicitly.
    ///
    /// Then, for every name whose required occurrence count is greater
    /// than 1 (i.e. every `alwaysOversignedHeaders` name, since its
    /// required count is always `actual + 1` -- 1 for an absent header, 2+
    /// for a present one), append a further pass repeating just those
    /// names, in the same relative order, until every name has appeared
    /// its required number of times. This "base pass, then repeat
    /// pass(es)" shape matches the convention RFC 8463 Appendix A's own
    /// worked example uses (`h=from : to : subject : date : message-id :
    /// from : subject : date` -- base list once, oversigned subset
    /// repeated a second time at the end) -- not merely an implementation
    /// convenience.
    ///
    /// Non-oversigned `signedHeaders` entries are included exactly at
    /// their actual occurrence count (0 if genuinely absent -- they are
    /// simply omitted from `h=` entirely, since only
    /// `alwaysOversignedHeaders` gets the "count+1, including zero"
    /// defensive treatment; a caller-listed header the composer never
    /// actually emits is not, on its own, a security-relevant injection
    /// target the way the fixed minimum set is).
    static func effectiveHeaderNames(
        signedHeaders: [String],
        actualHeaders: [(name: String, value: String)]
    ) -> [String] {
        var countsByLowerName: [String: Int] = [:]
        for (name, _) in actualHeaders {
            countsByLowerName[name.lowercased(), default: 0] += 1
        }

        var orderedNames: [String] = []
        var seen = Set<String>()
        for name in signedHeaders {
            let lower = name.lowercased()
            if !seen.contains(lower) {
                seen.insert(lower)
                orderedNames.append(lower)
            }
        }
        for name in alwaysOversignedHeaders where !seen.contains(name) {
            seen.insert(name)
            orderedNames.append(name)
        }

        var includeCounts: [String: Int] = [:]
        for name in orderedNames {
            let actual = countsByLowerName[name] ?? 0
            includeCounts[name] = alwaysOversignedHeaders.contains(name) ? actual + 1 : actual
        }

        let maxCount = includeCounts.values.max() ?? 0
        guard maxCount > 0 else { return [] }

        var flattened: [String] = []
        for pass in 0..<maxCount {
            for name in orderedNames where pass < (includeCounts[name] ?? 0) {
                flattened.append(name)
            }
        }
        return flattened
    }
}

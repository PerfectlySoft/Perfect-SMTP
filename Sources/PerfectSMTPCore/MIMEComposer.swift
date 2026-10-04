//
//  MIMEComposer.swift
//  PerfectSMTPCore
//
//  Builds the multipart shape from plan §4.7:
//    multipart/mixed [ multipart/related [ multipart/alternative [
//      text/plain, text/html ], inline CID images ], attachments ]
//  with empty layers collapsed (no attachments -> drop mixed; no inline
//  images -> drop related; single body -> drop alternative).
//

import Foundation

/// Internal MIME tree node. Not part of the public API — composition
/// collapses this into a flat `RFC5322Message` (top-level headers +
/// serialized body).
private struct MIMEPart {
    enum Body {
        case leaf([UInt8])
        indirect case multipart(boundary: String, parts: [MIMEPart])
    }
    var headers: [(name: String, value: String)]
    var body: Body
}

public struct MIMEComposer: Sendable {
    public enum ComposerError: Error, Sendable, Equatable {
        /// Neither `textBody` nor `htmlBody` was set — there is nothing to
        /// send as the primary content.
        case missingBody
        /// `extraHeaders` contained a name on `forbiddenExtraHeaderNames`
        /// — the reintroduction vector the Bug #1 fix closes.
        case forbiddenHeader(String)
        /// A header value (from `extraHeaders` or elsewhere) contained a
        /// raw CR or LF that survived sanitization — should not happen in
        /// practice since `sanitizeForHeader`-style stripping is applied
        /// upstream, but composition fails loudly rather than silently
        /// emitting a malformed header.
        case invalidHeaderValue(String)
        /// `EmailMessage.listUnsubscribe.postOneClick` was `true` but `url`
        /// was `nil` — RFC 8058 §2's one-click mechanism is specifically
        /// for the HTTPS POST target, so there is no URL for
        /// `List-Unsubscribe-Post` to describe. A caller configuration
        /// error, fails loud rather than silently omitting the header
        /// (matching this composer's existing `missingBody`/
        /// `forbiddenHeader` precedent for caller misconfiguration, as
        /// opposed to the silent-strip precedent reserved for free-text
        /// fields like Subject/display names).
        case postOneClickRequiresURL
        /// Milestone review finding (protocol pass, RFC 8058 §3.1 —
        /// "The List-Unsubscribe header field MUST contain one HTTPS URI"):
        /// `ListUnsubscribe.url` failed to parse as a URL at all, or parsed
        /// but its scheme was not `https`. Checked unconditionally whenever
        /// `url` is set — not only when `postOneClick` is true — since a
        /// plain (non-one-click) `List-Unsubscribe: <http://…>` target is
        /// also a cleartext-downgrade risk for whatever unsubscribe token
        /// it carries, even outside the one-click mechanism RFC 8058 §3.1
        /// literally addresses. Fails loud rather than silently downgrading
        /// or dropping the header, matching this composer's established
        /// caller-misconfiguration precedent (`postOneClickRequiresURL`,
        /// `forbiddenHeader`).
        case listUnsubscribeURLMustBeHTTPS
        /// Milestone review finding (security pass): `<`, `>`, and `,` are
        /// the delimiter characters RFC 8058/2369 use to structure
        /// `List-Unsubscribe`'s value as a comma-separated list of `<uri>`
        /// entries. Left unescaped in a caller-supplied `mailto`/`url`,
        /// they let a value splice an attacker-chosen extra entry into the
        /// header's own semantic list (e.g. `"https://good.example/unsub>,
        /// <mailto:spoofed@attacker.example"` injects a spoofed `mailto:`
        /// target) — a structural corruption distinct from the CR/LF
        /// line-injection class `invalidHeaderValue` already covers.
        /// Narrower in scope than `HeaderEncoder.rejectHeaderInjection`
        /// deliberately: these three characters are ordinary and often
        /// legitimate in other header fields (e.g. address angle-bracket
        /// syntax), so this check is List-Unsubscribe-specific rather than
        /// a broadening of the general injection check.
        case listUnsubscribeValueContainsDelimiterCharacter(String)
        /// `EmailMessage.bodyContentTypeOverride` and/or
        /// `bodyTransferEncodingOverride` was set, but the message has both
        /// `textBody` and `htmlBody` present — it composes to a
        /// `multipart/alternative` wrapper containing two leaf parts, so
        /// there is no single, unambiguous "the body" for a single-target
        /// override to mean. See `EmailMessage.bodyContentTypeOverride`'s
        /// doc comment for the full reasoning (the legacy Lasso
        /// `-contentType`/`-transferEncoding` params these overrides exist
        /// for are a simple, single-body send). Also sidesteps RFC 2045
        /// §6.4, which forbids giving a `multipart` entity any
        /// Content-Transfer-Encoding other than `7bit`/`8bit`/`binary` —
        /// applying `.quotedPrintable`/`.base64` to the wrapper itself
        /// would be a protocol violation, not just an ambiguous target.
        /// Fails loud rather than guessing, matching this composer's
        /// established caller-misconfiguration precedent
        /// (`postOneClickRequiresURL`, `forbiddenHeader`).
        case bodyOverrideRequiresSingleBodyPart
        /// `bodyTransferEncodingOverride == .sevenBit` but the body (the
        /// single `textBody` xor `htmlBody` leaf the override applies to)
        /// does not satisfy RFC 2045 §2.7's full definition of "7bit data"
        /// — a byte >= 0x80, an embedded NUL octet (0x00; excluded by §2.7
        /// even though it's < 0x80), or a line longer than 998 octets
        /// between CRLF sequences. Named more broadly than the original
        /// `...RequiresASCIIBody` (milestone review, protocol pass: the
        /// original name/check covered only the byte-range half of §2.7's
        /// definition) since all three conditions are the same class of
        /// mistake — RFC 2045 §6.2: "Labelling unencoded data containing
        /// 8bit characters as '7bit' is not allowed," and by the same logic,
        /// data that isn't valid 7bit data at all for any of §2.7's three
        /// reasons. Fails loud rather than emitting a mislabeled `7bit`
        /// part: an intermediate relay that trusts the `7bit` label would
        /// silently corrupt or misinterpret the message in transit.
        case sevenBitOverrideRequiresValidSevenBitBody
        /// `EmailMessage.bodyContentTypeOverride` carried a `charset=`
        /// parameter whose value was present but not UTF-8 (case-
        /// insensitive; `utf8` tolerated as an alias for `utf-8`).
        /// Milestone review finding (architecture + protocol passes,
        /// independently): this library has no transcoding engine anywhere
        /// — body bytes are always the Swift `String`'s UTF-8
        /// representation (see `bodyContentTypeOverride`'s doc comment for
        /// the full "no-transcoding" invariant) — so honoring a non-UTF-8
        /// `charset=` claim in the override would emit a `Content-Type`
        /// header describing bytes that were never actually produced,
        /// silently corrupting any non-ASCII body at the receiving end.
        /// Fails loud rather than emitting the mismatched claim, matching
        /// this composer's established caller-misconfiguration precedent.
        /// An override with no `charset=` parameter at all does not throw
        /// — this only fires when a charset is present and wrong.
        case bodyContentTypeOverrideCharsetMustBeUTF8
    }

    /// Case-insensitive denylist of header names `extraHeaders` may never
    /// use — envelope/routing-critical names, and names this composer
    /// already manages itself. Per plan §4.7: "strip/reject `Bcc`, `To`,
    /// `Cc`, `From`, `Return-Path`, and other envelope/routing-critical
    /// header names at composition time." This composer rejects (throws)
    /// rather than silently stripping, so a caller that tries to smuggle
    /// one of these back in gets a hard failure, not a quietly-dropped
    /// header.
    public static let forbiddenExtraHeaderNames: Set<String> = [
        "bcc", "to", "cc", "from", "sender", "reply-to", "return-path",
        "received", "message-id", "date", "mime-version", "content-type",
        "content-transfer-encoding", "content-disposition", "dkim-signature",
    ]

    public let message: EmailMessage
    public let charset: String
    private let messageIDDomain: String?
    private let boundaryGenerator: @Sendable () -> String
    private let now: @Sendable () -> Date

    /// - Parameters:
    ///   - messageIDDomain: Domain used to scope an auto-synthesized
    ///     `Message-ID` when `message.messageID` is nil. Phase 0 has no
    ///     DKIM `d=`/envelope-from to scope to yet (that's wired up in
    ///     Phase 1/2), so when this is left nil the composer falls back to
    ///     the domain portion of `message.from.address` — the closest
    ///     "coherent" domain actually available at this phase. Callers
    ///     (and later phases) may override explicitly.
    ///   - boundaryGenerator: Produces MIME boundary strings; overridable
    ///     for deterministic golden-fixture tests.
    ///   - charset: Overrides `message.charset` when non-nil. `EmailMessage`
    ///     already carries its own `charset` field (plan §4.7, mirroring
    ///     Lasso's per-send `-characterSet`), which is what's actually used
    ///     for encoding text parts when this parameter is left nil — the
    ///     default. This parameter exists to match the plan §4.9 two-phase
    ///     API sketch (`MIMEComposer(msg, charset: "utf-8").compose()`)
    ///     while keeping `message.charset` as the single source of truth
    ///     for the common case where a caller doesn't need to override it
    ///     independently of the message itself.
    public init(
        _ message: EmailMessage,
        charset: String? = nil,
        messageIDDomain: String? = nil,
        boundaryGenerator: @escaping @Sendable () -> String = MIMEComposer.defaultBoundaryGenerator,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.message = message
        self.charset = charset ?? message.charset
        self.messageIDDomain = messageIDDomain
        self.boundaryGenerator = boundaryGenerator
        self.now = now
    }

    public static func defaultBoundaryGenerator() -> String {
        "perfect-smtp-\(UUID().uuidString)"
    }

    /// Routes a caller-controlled string through `HeaderEncoder`'s shared
    /// `rejectHeaderInjection`, re-surfacing any control-character rejection
    /// as this composer's own `ComposerError.invalidHeaderValue` — the
    /// single call site every one of the milestone review's newly-covered
    /// fields (`extraHeaders` names, `messageID`, `inReplyTo`, `references`,
    /// attachment/inline `Content-Type`) goes through, so the fail-loud
    /// discipline stays centralized in `HeaderEncoder` rather than being
    /// re-implemented per field here.
    private static func requireNoInjection(_ value: String, field: String) throws {
        do {
            _ = try HeaderEncoder.rejectHeaderInjection(value, field: field)
        } catch is HeaderEncoder.HeaderInjectionError {
            throw ComposerError.invalidHeaderValue(field)
        }
    }

    public func compose() throws -> RFC5322Message {
        for (name, value) in message.extraHeaders {
            // Milestone review finding: the name was never checked for
            // CR/LF, only the value — a mangled name like
            // "X-Foo\r\nBcc" passed both the (name-based) denylist check
            // and the (CR/LF-free) value check, a total bypass of the
            // denylist that exists specifically to prevent this. Checked
            // first, before the denylist lookup, so a mangled name is
            // caught regardless of what it lowercases to.
            try Self.requireNoInjection(name, field: name)
            if Self.forbiddenExtraHeaderNames.contains(name.lowercased()) {
                throw ComposerError.forbiddenHeader(name)
            }
            try Self.requireNoInjection(value, field: name)
        }
        guard message.textBody != nil || message.htmlBody != nil else {
            throw ComposerError.missingBody
        }

        let top = try buildTopLevelPart()

        var headers: [(name: String, value: String)] = []
        headers.append(("From", try HeaderEncoder.encodeAddress(message.from)))
        if let sender = message.sender {
            headers.append(("Sender", try HeaderEncoder.encodeAddress(sender)))
        }
        if !message.replyTo.isEmpty {
            headers.append(("Reply-To", try HeaderEncoder.encodeAddressList(message.replyTo)))
        }
        if !message.to.isEmpty {
            headers.append(("To", try HeaderEncoder.encodeAddressList(message.to)))
        }
        if !message.cc.isEmpty {
            headers.append(("Cc", try HeaderEncoder.encodeAddressList(message.cc)))
        }

        headers.append(("Date", Self.rfc5322DateString(message.date ?? now())))
        if let messageID = message.messageID {
            // Only the caller-supplied case needs validating — the
            // synthesized fallback is a UUID plus a domain already
            // validated above via the "From" header's `encodeAddress`
            // call, so it can't carry an injection payload.
            try Self.requireNoInjection(messageID, field: "messageID")
            headers.append(("Message-ID", messageID))
        } else {
            headers.append(("Message-ID", synthesizeMessageID()))
        }

        if let inReplyTo = message.inReplyTo {
            try Self.requireNoInjection(inReplyTo, field: "inReplyTo")
            headers.append(("In-Reply-To", inReplyTo))
        }
        if !message.references.isEmpty {
            for reference in message.references {
                try Self.requireNoInjection(reference, field: "references")
            }
            headers.append(("References", message.references.joined(separator: " ")))
        }

        headers.append(("Subject", HeaderEncoder.encodeUnstructured(message.subject)))
        headers.append(contentsOf: Self.priorityHeaders(message.priority))

        // Deliverability-hygiene headers (plan §7/§8, Phase 5): order
        // relative to the rest of these general headers is not otherwise
        // significant — confirmed against this codebase's one order-
        // sensitive consumer, DKIM's `h=` canonicalization
        // (`DKIMSigningInput`/`DKIMSigner`, Phase 2), which signs based on
        // the actual header list *passed to the signer* (looked up by
        // name against the already-composed message), not a fixed
        // position, so inserting headers here doesn't disturb it.
        headers.append(contentsOf: try listUnsubscribeHeaders())
        if let precedence = message.precedence {
            headers.append(("Precedence", precedence.rawValue))
        }
        if let autoSubmitted = message.autoSubmitted {
            headers.append(("Auto-Submitted", autoSubmitted.rawValue))
        }

        headers.append(("MIME-Version", "1.0"))
        headers.append(contentsOf: top.headers)
        headers.append(contentsOf: message.extraHeaders)

        let body: [UInt8]
        switch top.body {
        case .leaf(let bytes):
            body = bytes
        case .multipart(let boundary, let parts):
            body = Self.serializeMultipart(boundary: boundary, parts: parts)
        }

        return RFC5322Message(headers: headers, body: body)
    }

    /// Builds `List-Unsubscribe`/`List-Unsubscribe-Post` (RFC 8058, building
    /// on the older RFC 2369) from `message.listUnsubscribe`, or `[]` when
    /// unset. Both `mailto` and `url` are caller-supplied strings reaching
    /// a raw header value exactly like the fields Phase 0's original
    /// CRLF-injection fix covered — routed through the same
    /// `requireNoInjection` (⇒ `HeaderEncoder.rejectHeaderInjection`)
    /// discipline as every other caller-controlled header value in this
    /// file, not a new, separately-invented check.
    ///
    /// Emission rules:
    /// - `List-Unsubscribe` lists whichever of `mailto`/`url` are present,
    ///   each wrapped in angle brackets, comma-separated if both — e.g.
    ///   `<mailto:unsub@example.com>, <https://example.com/unsub?id=123>`.
    ///   `mailto` is prefixed with the `mailto:` scheme here; `url` is
    ///   used verbatim (it already carries its own scheme).
    /// - Neither present (or `message.listUnsubscribe` itself is `nil`) →
    ///   no headers at all.
    /// - `postOneClick == true` requires `url` to be set — checked first,
    ///   unconditionally, regardless of whether `mailto` is also present —
    ///   since a caller who sets `postOneClick` with no `url` has made a
    ///   configuration mistake this composer should surface, not paper
    ///   over (`ComposerError.postOneClickRequiresURL`).
    /// - `url`, whenever present, MUST be an `https://` URI — checked
    ///   unconditionally, not only when `postOneClick` is true (milestone
    ///   review, RFC 8058 §3.1; see `ComposerError.listUnsubscribeURLMustBeHTTPS`'s
    ///   doc comment for the always-vs-one-click-only scope decision).
    ///   Parsed with `Foundation.URL(string:)`; a string that fails to
    ///   parse at all is treated the same as one that parses but isn't
    ///   `https` — both are a caller configuration error.
    /// - `mailto`/`url` may not contain `<`, `>`, or `,` — RFC 8058/2369's
    ///   own list-delimiter characters, which would otherwise splice an
    ///   extra, attacker-chosen entry into the header's value list
    ///   (milestone review, security pass; see
    ///   `ComposerError.listUnsubscribeValueContainsDelimiterCharacter`'s
    ///   doc comment). Checked in addition to, not instead of, the
    ///   existing CR/LF-injection check below.
    /// - A `mailto` value that already starts with the `mailto:` scheme
    ///   (case-insensitively) has the redundant prefix stripped before the
    ///   scheme is re-added, rather than producing a doubled-scheme
    ///   `mailto:mailto:…` URI (milestone review, robustness pass) — `mailto`
    ///   is documented as the bare mailbox, so this treats the prefixed
    ///   form as a caller mistake worth silently correcting rather than a
    ///   hard failure, consistent with this file's existing precedent of
    ///   reserving `throw` for genuinely ambiguous/dangerous input (CRLF,
    ///   delimiter splicing) rather than a merely redundant-but-unambiguous
    ///   one.
    /// - `List-Unsubscribe-Post: List-Unsubscribe=One-Click` is emitted
    ///   verbatim when `postOneClick` is true — this value is a fixed
    ///   literal per RFC 8058 §2, never caller-configurable.
    private func listUnsubscribeHeaders() throws -> [(name: String, value: String)] {
        guard let config = message.listUnsubscribe else { return [] }
        if config.postOneClick, config.url == nil {
            throw ComposerError.postOneClickRequiresURL
        }

        var entries: [String] = []
        if let mailto = config.mailto {
            try Self.requireNoInjection(mailto, field: "listUnsubscribe.mailto")
            try Self.requireNoListUnsubscribeDelimiters(mailto, field: "listUnsubscribe.mailto")
            entries.append("<mailto:\(Self.strippingRedundantMailtoScheme(mailto))>")
        }
        if let url = config.url {
            try Self.requireNoInjection(url, field: "listUnsubscribe.url")
            try Self.requireNoListUnsubscribeDelimiters(url, field: "listUnsubscribe.url")
            try Self.requireHTTPSListUnsubscribeURL(url)
            entries.append("<\(url)>")
        }
        guard !entries.isEmpty else { return [] }

        var headers: [(name: String, value: String)] = [
            ("List-Unsubscribe", entries.joined(separator: ", ")),
        ]
        if config.postOneClick {
            headers.append(("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"))
        }
        return headers
    }

    /// RFC 8058 §3.1's `mailto`-doesn't-need-a-scheme-prefix convention:
    /// strips a redundant, caller-supplied `mailto:` prefix (case-
    /// insensitively) so `listUnsubscribeHeaders()` never emits a doubled
    /// `mailto:mailto:…` URI.
    private static func strippingRedundantMailtoScheme(_ mailto: String) -> String {
        let prefix = "mailto:"
        guard mailto.lowercased().hasPrefix(prefix) else { return mailto }
        return String(mailto.dropFirst(prefix.count))
    }

    /// FIX #3 (milestone review, security pass): rejects the three
    /// characters (`<`, `>`, `,`) RFC 8058/2369 use to delimit
    /// `List-Unsubscribe`'s comma-separated `<uri>` list — deliberately
    /// separate from, and in addition to, `requireNoInjection`'s CR/LF
    /// check, and deliberately not folded into `HeaderEncoder.rejectHeaderInjection`
    /// itself (those characters are legitimate in other header fields,
    /// e.g. address angle-bracket syntax).
    private static func requireNoListUnsubscribeDelimiters(_ value: String, field: String) throws {
        guard value.contains(where: { $0 == "<" || $0 == ">" || $0 == "," }) else { return }
        throw ComposerError.listUnsubscribeValueContainsDelimiterCharacter(field)
    }

    /// FIX #1 (milestone review, protocol pass): RFC 8058 §3.1 — "The
    /// List-Unsubscribe header field MUST contain one HTTPS URI." Applied
    /// unconditionally to `listUnsubscribe.url` whenever it's set, not only
    /// when `postOneClick` is true — see `ComposerError.listUnsubscribeURLMustBeHTTPS`'s
    /// doc comment for the scope rationale.
    private static func requireHTTPSListUnsubscribeURL(_ value: String) throws {
        guard let url = Foundation.URL(string: value), url.scheme?.lowercased() == "https" else {
            throw ComposerError.listUnsubscribeURLMustBeHTTPS
        }
    }

    // MARK: - Tree construction

    private func buildTopLevelPart() throws -> MIMEPart {
        // `bodyContentTypeOverride`/`bodyTransferEncodingOverride` only ever
        // have a single, unambiguous target: the lone `textBody` xor
        // `htmlBody` leaf. When both are present the message composes to a
        // `multipart/alternative` wrapper instead of one leaf, so a caller
        // who set either override alongside both bodies has made a
        // configuration mistake this composer surfaces rather than papers
        // over — see `ComposerError.bodyOverrideRequiresSingleBodyPart`'s
        // doc comment. Checked before building either leaf so the error is
        // reported regardless of which leaf would otherwise "win".
        if message.textBody != nil, message.htmlBody != nil,
           message.bodyContentTypeOverride != nil || message.bodyTransferEncodingOverride != nil {
            throw ComposerError.bodyOverrideRequiresSingleBodyPart
        }

        var bodyParts: [MIMEPart] = []
        if let text = message.textBody {
            bodyParts.append(try textLeaf(text, subtype: "plain"))
        }
        if let html = message.htmlBody {
            bodyParts.append(try textLeaf(html, subtype: "html"))
        }

        let alternativeOrSingle: MIMEPart
        if bodyParts.count > 1 {
            let boundary = boundaryGenerator()
            alternativeOrSingle = MIMEPart(
                headers: [("Content-Type", "multipart/alternative; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: bodyParts)
            )
        } else {
            alternativeOrSingle = bodyParts[0]
        }

        let relatedOrSingle: MIMEPart
        if !message.inlineImages.isEmpty {
            let boundary = boundaryGenerator()
            var parts = [alternativeOrSingle]
            parts.append(contentsOf: try message.inlineImages.map(inlineLeaf))
            relatedOrSingle = MIMEPart(
                headers: [("Content-Type", "multipart/related; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: parts)
            )
        } else {
            relatedOrSingle = alternativeOrSingle
        }

        if !message.attachments.isEmpty {
            let boundary = boundaryGenerator()
            var parts = [relatedOrSingle]
            parts.append(contentsOf: try message.attachments.map(attachmentLeaf))
            return MIMEPart(
                headers: [("Content-Type", "multipart/mixed; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: parts)
            )
        }
        return relatedOrSingle
    }

    /// Builds a `text/plain` or `text/html` leaf part. When
    /// `message.bodyContentTypeOverride`/`bodyTransferEncodingOverride` are
    /// set, this is guaranteed by `buildTopLevelPart`'s single-body-part
    /// guard to be the *only* body leaf being built for this message, so
    /// applying the override here unconditionally (no further "is this the
    /// right part" check needed) is safe.
    private func textLeaf(_ text: String, subtype: String) throws -> MIMEPart {
        // Computed once and reused by every branch below: this is also the
        // exact byte sequence that gets sent on the wire whenever the body
        // isn't further transformed (7bit/nil paths), so RFC 2045 §2.7
        // "7bit data" validation runs against these bytes, not the raw
        // (possibly bare-CR/LF) `text` — normalizeLineEndings already
        // guarantees CR/LF only ever appear here as CRLF pairs, so "octets
        // between CRLF sequences" (§2.7's line definition) reduces to
        // counting octets between the CRLF pairs actually present.
        let normalizedBytes = Array(normalizeLineEndings(text).utf8)

        let contentType: String
        if let override = message.bodyContentTypeOverride {
            try Self.requireNoInjection(override, field: "bodyContentTypeOverride")
            try Self.requireUTF8CharsetIfPresent(override)
            contentType = override
        } else {
            // Milestone review finding (security pass): `charset` (from
            // `EmailMessage.charset`, i.e. Lasso's `-characterSet`) reaches
            // this default `Content-Type` header exactly like `override`
            // does above, but was never routed through
            // `requireNoInjection` -- a caller-supplied charset containing
            // CR/LF was embedded verbatim, letting a value like
            // `"utf-8\r\nBcc: attacker@evil.com"` inject an arbitrary extra
            // header. `bodyContentTypeOverride` already got this exact
            // protection when it was added; this closes the same gap for
            // the non-override (default) path, so `EmailMessage.charset`
            // is protected for every caller, not just ones that also set
            // an override.
            try Self.requireNoInjection(charset, field: "charset")
            contentType = "text/\(subtype); charset=\(charset)"
        }

        let cte: String
        let bodyBytes: [UInt8]
        switch message.bodyTransferEncodingOverride {
        case .sevenBit:
            // RFC 2045 §6.2: "Labelling unencoded data containing 8bit
            // characters as '7bit' is not allowed," and more generally RFC
            // 2045 §2.7's full definition of "7bit data" (no byte >= 0x80,
            // no NUL octet, no line > 998 octets between CRLF sequences —
            // see `isValidSevenBitData`). Validated against the actual
            // bytes, not just trusted, since a caller-supplied label that
            // doesn't match the real content is exactly the
            // transit-corruption risk this override exists to avoid
            // reopening.
            guard Self.isValidSevenBitData(normalizedBytes) else {
                throw ComposerError.sevenBitOverrideRequiresValidSevenBitBody
            }
            cte = "7bit"
            bodyBytes = normalizedBytes
        case .quotedPrintable:
            // Always representable regardless of body content — genuinely
            // applies RFC 2045 §6.7 encoding to the bytes (not just a header
            // label), same `Encoders.quotedPrintable` used by the
            // auto-computed non-ASCII path below.
            cte = "quoted-printable"
            bodyBytes = Array(Encoders.quotedPrintable(text).utf8)
        case .base64:
            // Always representable regardless of body content — genuinely
            // applies RFC 2045 §6.8 encoding to the bytes (not just a header
            // label), same `Encoders.base64Wrapped` used by attachments/
            // inline resources. Line endings are normalized to CRLF first
            // (RFC 2045's canonical form for text media) before being
            // base64-encoded, matching the 7bit/quoted-printable paths.
            cte = "base64"
            bodyBytes = Array(Encoders.base64Wrapped(Data(normalizedBytes)).utf8)
        case nil:
            // No override — auto-computed behavior. Milestone review
            // (protocol pass): this path had the same pre-existing gap the
            // `.sevenBit` override path had before this fix — it checked
            // only the byte-range half of RFC 2045 §2.7's "7bit data"
            // definition, so a body that was all-ASCII but contained a NUL
            // octet or an overlong line was mislabeled `7bit` here too.
            // Fixed identically to the override path above, for consistency
            // (see `isValidSevenBitData`) — a body that fails the full
            // §2.7 check now falls through to the same quoted-printable
            // path a non-ASCII body already used, rather than being
            // mislabeled. This is a strict improvement over the prior
            // default behavior, not a new risk: nothing that used to
            // qualify as valid 7bit data stops qualifying, so no
            // conforming existing caller is affected.
            if Self.isValidSevenBitData(normalizedBytes) {
                cte = "7bit"
                bodyBytes = normalizedBytes
            } else {
                cte = "quoted-printable"
                bodyBytes = Array(Encoders.quotedPrintable(text).utf8)
            }
        }

        return MIMEPart(
            headers: [
                ("Content-Type", contentType),
                ("Content-Transfer-Encoding", cte),
            ],
            body: .leaf(bodyBytes)
        )
    }

    /// RFC 2045 §2.7's full definition of "7bit data": "data that is all
    /// represented as relatively short lines with 998 octets or less
    /// between CRLF line separation sequences. No octets with decimal
    /// values greater than 127 are allowed and neither are NULs (octets
    /// with decimal value 0)." (CR/LF occurring only as part of a CRLF pair
    /// is guaranteed upstream by `normalizeLineEndings`, so that third
    /// sub-condition doesn't need a separate check here.) `bytes` is assumed
    /// to already be CRLF-normalized (i.e. the output of
    /// `normalizeLineEndings(_:).utf8`), matching every call site.
    private static func isValidSevenBitData(_ bytes: [UInt8]) -> Bool {
        guard bytes.allSatisfy({ $0 < 0x80 && $0 != 0x00 }) else { return false }
        var lineLength = 0
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x0D, index + 1 < bytes.count, bytes[index + 1] == 0x0A {
                lineLength = 0
                index += 2
                continue
            }
            lineLength += 1
            if lineLength > 998 { return false }
            index += 1
        }
        return true
    }

    /// FIX #1 (milestone review, architecture + protocol passes): tolerant
    /// extraction of a `charset=` parameter's value from a caller-supplied
    /// `Content-Type`-shaped string, and rejection if present-and-not-UTF-8.
    /// Deliberately not a full RFC 2045 header-parameter parser — just a
    /// `;`-split, case-insensitive-on-the-parameter-name, quote-tolerant
    /// extraction of `charset=VALUE` / `charset="VALUE"`, sufficient to
    /// catch the mismatched-label class of bug this guards against without
    /// implementing a general MIME header grammar for a single field. A
    /// missing `charset=` parameter is not an error — this only rejects a
    /// charset that is present and resolves to something other than UTF-8.
    private static func requireUTF8CharsetIfPresent(_ contentTypeOverride: String) throws {
        guard let charsetValue = extractCharsetParameter(from: contentTypeOverride) else { return }
        let normalized = charsetValue.lowercased()
        guard normalized == "utf-8" || normalized == "utf8" else {
            throw ComposerError.bodyContentTypeOverrideCharsetMustBeUTF8
        }
    }

    private static func extractCharsetParameter(from contentType: String) -> String? {
        for rawParam in contentType.split(separator: ";") {
            let param = rawParam.trimmingCharacters(in: .whitespaces)
            guard let equalsIndex = param.firstIndex(of: "=") else { continue }
            let name = param[param.startIndex..<equalsIndex].trimmingCharacters(in: .whitespaces)
            guard name.lowercased() == "charset" else { continue }
            var value = param[param.index(after: equalsIndex)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }
            return value
        }
        return nil
    }

    private func attachmentLeaf(_ attachment: Attachment) throws -> MIMEPart {
        // Milestone review finding: `contentType` was interpolated raw
        // into this part's own Content-Type header line — a value like
        // "text/plain\r\nX-Injected-CT: yes" injected an extra header
        // line inside the attachment's own part.
        try Self.requireNoInjection(attachment.contentType, field: "attachment.contentType")
        let disposition = attachment.disposition ?? message.defaultDisposition
        let name = sanitizedFilename(attachment.filename)
        return MIMEPart(
            headers: [
                ("Content-Type", "\(attachment.contentType); \(Self.filenameParameter("name", name))"),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", "\(disposition.rawValue); \(Self.filenameParameter("filename", name))"),
            ],
            body: .leaf(Array(Encoders.base64Wrapped(attachment.data).utf8))
        )
    }

    private func inlineLeaf(_ resource: InlineResource) throws -> MIMEPart {
        try Self.requireNoInjection(resource.contentType, field: "inlineResource.contentType")
        var headers: [(name: String, value: String)] = []
        if let filename = resource.filename {
            let name = sanitizedFilename(filename)
            headers.append(("Content-Type", "\(resource.contentType); \(Self.filenameParameter("name", name))"))
            headers.append(("Content-Transfer-Encoding", "base64"))
            headers.append(("Content-ID", "<\(resource.contentID)>"))
            headers.append(("Content-Disposition", "inline; \(Self.filenameParameter("filename", name))"))
        } else {
            headers.append(("Content-Type", resource.contentType))
            headers.append(("Content-Transfer-Encoding", "base64"))
            headers.append(("Content-ID", "<\(resource.contentID)>"))
            headers.append(("Content-Disposition", "inline"))
        }
        return MIMEPart(headers: headers, body: .leaf(Array(Encoders.base64Wrapped(resource.data).utf8)))
    }

    // MARK: - Serialization

    private static func serializeMultipart(boundary: String, parts: [MIMEPart]) -> [UInt8] {
        var out = [UInt8]()
        for part in parts {
            out.append(contentsOf: Array("--\(boundary)\r\n".utf8))
            for (name, value) in part.headers {
                out.append(contentsOf: Array("\(name): \(value)\r\n".utf8))
            }
            out.append(contentsOf: Array("\r\n".utf8))
            switch part.body {
            case .leaf(let bytes):
                out.append(contentsOf: bytes)
            case .multipart(let innerBoundary, let innerParts):
                out.append(contentsOf: serializeMultipart(boundary: innerBoundary, parts: innerParts))
            }
            out.append(contentsOf: Array("\r\n".utf8))
        }
        out.append(contentsOf: Array("--\(boundary)--\r\n".utf8))
        return out
    }

    // MARK: - Helpers

    private func normalizeLineEndings(_ text: String) -> String {
        text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
    }

    /// Strips control characters (including CR/LF) from a caller-supplied
    /// filename before it's embedded in a header parameter — defensive
    /// against header injection via an attacker-controlled upload
    /// filename. Non-ASCII filenames are then encoded by
    /// `filenameParameter` (RFC 2231).
    ///
    /// Also hardened against path traversal (milestone review finding):
    /// a filename like "../../../../etc/passwd" previously passed straight
    /// through into `Content-Disposition: attachment; filename="..."`.
    /// Basename the string — keep only the component after the last path
    /// separator (`/` or `\`, covering both POSIX and Windows-style
    /// caller input, including stripping a leading drive letter as a side
    /// effect of basenaming) — then strip any remaining leading dots.
    private func sanitizedFilename(_ name: String) -> String {
        let controlFree = String(
            String.UnicodeScalarView(name.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7F })
        )
        let lastSeparator = controlFree.lastIndex(where: { $0 == "/" || $0 == "\\" })
        let base = lastSeparator.map { String(controlFree[controlFree.index(after: $0)...]) } ?? controlFree
        let noLeadingDots = String(base.drop(while: { $0 == "." }))
        return noLeadingDots.isEmpty ? "_" : noLeadingDots
    }

    private static func quotedParam(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// A `name` / `filename` parameter for a (sanitized) filename.
    ///
    /// Printable ASCII is sent as before: `filename="report.pdf"`. Anything else gets an
    /// ASCII fallback for old clients plus the RFC 2231 extended value modern clients read:
    ///
    ///     filename="R_sum_.pdf";
    ///      filename*=utf-8''R%C3%A9sum%C3%A9.pdf
    ///
    /// A long extended value is split into `filename*0*=`, `filename*1*=`, ... continuations
    /// (RFC 2231 §3-4) on folded lines, never inside a `%XX` escape.
    static func filenameParameter(_ parameter: String, _ value: String) -> String {
        if value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value < 0x7F }) {
            return "\(parameter)=\"\(quotedParam(value))\""
        }
        let fallback = String(String.UnicodeScalarView(value.unicodeScalars.map { $0.value < 0x7F ? $0 : "_" }))
        // RFC 2231 attribute-char: printable ASCII except space, "*", "'", "%" and tspecials.
        let attributeChars = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&+-.^_`|~".utf8)
        let tokens = value.utf8.map { byte in
            attributeChars.contains(byte) ? String(UnicodeScalar(byte)) : String(format: "%%%02X", byte)
        }
        // Keep every folded line within RFC 5322's 78-character recommendation: leading space,
        // `name*NN*=`, the `utf-8''` prefix (first segment only, but budget it everywhere) and `;`.
        let segmentLength = 78 - (1 + parameter.count + "*99*=".count + "utf-8''".count + 1)
        var segments: [String] = [""]
        for token in tokens {
            if segments[segments.count - 1].count + token.count > segmentLength {
                segments.append("")
            }
            segments[segments.count - 1] += token
        }
        let extended: String
        if segments.count == 1 {
            extended = "\(parameter)*=utf-8''\(segments[0])"
        } else {
            extended = segments.enumerated().map { index, segment in
                "\(parameter)*\(index)*=" + (index == 0 ? "utf-8''" : "") + segment
            }.joined(separator: ";\r\n ")
        }
        return "\(parameter)=\"\(quotedParam(fallback))\";\r\n \(extended)"
    }

    private func synthesizeMessageID() -> String {
        let domain = messageIDDomain ?? Self.domain(from: message.from.address)
        return "<\(UUID().uuidString)@\(domain)>"
    }

    private static func domain(from address: String) -> String {
        guard let atIndex = address.lastIndex(of: "@") else { return "localhost.invalid" }
        let domainPart = address[address.index(after: atIndex)...]
        return domainPart.isEmpty ? "localhost.invalid" : String(domainPart)
    }

    private static func priorityHeaders(_ priority: Priority) -> [(name: String, value: String)] {
        switch priority {
        case .normal: return []
        case .high: return [("X-Priority", "1"), ("Importance", "High")]
        case .low: return [("X-Priority", "5"), ("Importance", "Low")]
        }
    }

    /// RFC 5322 §3.3 date-time string, hand-rolled (no `DateFormatter`) so
    /// this stays free of any shared, non-`Sendable` global formatter
    /// state and formats identically on Linux and Darwin. Always uses
    /// English day/month names regardless of the running locale, per RFC
    /// 5322's fixed vocabulary — a `Locale.current`-driven `DateFormatter`
    /// (as the original implementation used) would silently localize these
    /// and break the header on non-English systems.
    public static func rfc5322DateString(_ date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let comps = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second, .weekday], from: date)

        let dayNames = ["", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        let monthNames = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        let weekday = dayNames[comps.weekday ?? 1]
        let month = monthNames[comps.month ?? 1]

        let offsetSeconds = timeZone.secondsFromGMT(for: date)
        let sign = offsetSeconds >= 0 ? "+" : "-"
        let absOffset = abs(offsetSeconds)

        return "\(weekday), \(pad2(comps.day ?? 1)) \(month) \(pad4(comps.year ?? 1970)) " +
            "\(pad2(comps.hour ?? 0)):\(pad2(comps.minute ?? 0)):\(pad2(comps.second ?? 0)) " +
            "\(sign)\(pad2(absOffset / 3600))\(pad2((absOffset % 3600) / 60))"
    }

    private static func pad2(_ n: Int) -> String { n < 10 ? "0\(n)" : "\(n)" }
    private static func pad4(_ n: Int) -> String {
        let s = "\(n)"
        return s.count >= 4 ? s : String(repeating: "0", count: 4 - s.count) + s
    }
}

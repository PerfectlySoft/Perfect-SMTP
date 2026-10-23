//
//  HeaderEncoder.swift
//  PerfectSMTPCore
//
//  Real RFC 2047 encoded-words — this is Bug #2's actual fix (plan §4.7).
//  The old code emitted a fake, unescaped
//  `Subject: =?utf-8?Q?<raw>?=` for any subject that didn't happen to hit
//  the base64 branch. Two corrections called out explicitly by the
//  protocol review are implemented here:
//
//  (a) Folding at the 75-char-per-encoded-word limit happens on Unicode
//      scalar (character) boundaries only — a byte-oriented fold can cut a
//      multi-byte UTF-8 sequence in half, producing mojibake on decode.
//  (b) Encoded-words are never emitted inside an RFC 5322 quoted-string
//      (RFC 2047 §5 forbids it — a receiver that sees `"=?utf-8?B?…?="`
//      would treat it as literal text, not decode it). Non-ASCII phrases
//      are always emitted as bare encoded-words; ASCII-but-special-
//      character phrases use an ordinary quoted-string; never both on the
//      same phrase.
//
//  Milestone review finding (architect/protocol/security passes, all
//  independently converging on the same root cause): the CR/LF-stripping
//  sanitization here was originally applied only to Subject text and
//  display-name phrases (`sanitizeForHeader`, below), never extended to
//  the other caller-controlled strings that also end up embedded raw into
//  an RFC 5322 header line or an SMTP command line — reopening Bug #1
//  (the Bcc-header-leak bug) through addresses, `extraHeaders` names,
//  `Message-ID`/`In-Reply-To`/`References`, MIME part `Content-Type`, and
//  the SMTP `MAIL FROM`/`RCPT TO` command lines. `rejectHeaderInjection`
//  below is the single, uniformly-applied discipline every one of those
//  call sites now routes through, instead of another set of scattered
//  per-field patches.
//

import Foundation

public enum HeaderEncoder {
    /// Maximum total length of one `=?charset?enc?...?=` token, per RFC 2047 §2.
    private static let maxEncodedWordLength = 75
    /// `"=?utf-8?B?" + "?="` fixed overhead around the base64 payload = 12
    /// characters. Payload capped at 45 bytes so the base64 expansion
    /// (ceil(45/3)*4 = 60 chars) plus overhead stays comfortably at or
    /// under `maxEncodedWordLength`.
    private static let maxPayloadBytesPerWord = 39 // 52 base64 chars + 12 = 64, so "Subject: " plus a word stays under 78

    private static let atextChars: Set<Character> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
    )

    /// Encodes an unstructured header value (e.g. `Subject`) per RFC 2047.
    /// Pure-ASCII, control-character-free input is returned unmodified;
    /// anything else is emitted as one or more folded encoded-words.
    public static func encodeUnstructured(_ text: String) -> String {
        let sanitized = sanitizeForHeader(text)
        // A run without whitespace can't be folded; past 900 octets it
        // would break the 998-octet line limit, so encode it instead
        // (encoded words are folded between words).
        guard needsEncoding(sanitized) || longestUnbreakableRun(sanitized) > 900 else { return sanitized }
        return encodedWords(for: sanitized).joined(separator: "\r\n ")
    }

    /// Encodes an RFC 5322 `phrase` (e.g. a mailbox display name).
    /// ASCII phrases that are plain space-separated atoms are emitted bare;
    /// ASCII phrases needing quoting (commas, quotes, etc.) become an
    /// ordinary `quoted-string`; any non-ASCII content is emitted as
    /// encoded-word(s) — never combined with quoting on the same phrase.
    public static func encodePhrase(_ text: String) -> String {
        let sanitized = sanitizeForHeader(text)
        guard !sanitized.isEmpty else { return sanitized }
        if sanitized.utf8.allSatisfy({ $0 < 0x80 }) {
            return isPlainAtomsPhrase(sanitized) ? sanitized : quotedString(sanitized)
        }
        return encodedWords(for: sanitized).joined(separator: "\r\n ")
    }

    /// Encodes one mailbox as `phrase <addr-spec>`, or just the addr-spec
    /// if there's no display name.
    ///
    /// The addr-spec itself (unlike the display-name phrase, which goes
    /// through `encodePhrase`'s silent `sanitizeForHeader` stripping) is
    /// routed through the fail-loud `rejectHeaderInjection` instead:
    /// silently stripping CR/LF out of an address could mask a real caller
    /// bug (a mangled address is a caller-visible error, not something to
    /// quietly "fix" into a different, unintended address), matching this
    /// codebase's existing `extraHeaders`-value precedent
    /// (`ComposerError.invalidHeaderValue`, thrown rather than stripped).
    public static func encodeAddress(_ address: EmailAddress) throws -> String {
        let addrSpec = try rejectHeaderInjection(address.address, field: "address")
        // A plain mailbox only: `s@example.test>, <attacker@evil.test`
        // would otherwise add a second mailbox to the header.
        try AddressSyntax.validateMailbox(addrSpec, field: "address")
        guard let name = address.displayName, !name.isEmpty else {
            return addrSpec
        }
        return "\(encodePhrase(name)) <\(addrSpec)>"
    }

    /// Encodes a comma-separated mailbox list for `To:`/`Cc:`/`Reply-To:`.
    public static func encodeAddressList(_ addresses: [EmailAddress]) throws -> String {
        try addresses.map { try encodeAddress($0) }.joined(separator: ", ")
    }

    // MARK: - Internals

    /// Thrown by `rejectHeaderInjection` when a caller-controlled string
    /// destined for a header line or SMTP command line contains a control
    /// character that could be used to inject an additional line.
    public enum HeaderInjectionError: Error, Sendable, Equatable {
        case controlCharacterInField(String)
        /// Milestone review finding (FIX #2, security pass): an address
        /// destined for `LocalMTATransport`'s `sendmail -f`/recipient argv
        /// that starts with `-` would otherwise be interpreted by the local
        /// MTA's `getopt`-style argv parser as a command-line flag, not a
        /// literal address (CWE-88 / the CVE-2016-10033-class PHPMailer/
        /// SwiftMailer vulnerability). Distinct from
        /// `controlCharacterInField` since this isn't a control-character
        /// injection -- a leading `-` is a perfectly ordinary, printable
        /// character in isolation, and only becomes dangerous in the
        /// specific context of an argv element.
        case leadingHyphenInField(String)
    }

    /// True for any C0 control character (0x00–0x1F), DEL (0x7F) — the
    /// character class that must never survive, unescaped, into a string
    /// bound for an RFC 5322 header line or an SMTP command line. This is
    /// broader than just CR/LF: it also covers other C0 controls such as
    /// ESC (0x1B), which are not RFC 5322-structure injection vectors but
    /// are a terminal-escape-sequence-injection risk for any tool that
    /// renders headers to a terminal without its own escaping (milestone
    /// review finding — a `quoted-string` only escapes `\` and `"`, not
    /// control characters, so a control byte in a display name survives
    /// straight through `quotedString` below).
    ///
    /// Release review: also the C1 controls (U+0080–U+009F, including NEL
    /// U+0085) and the Unicode line and paragraph separators U+2028/U+2029,
    /// which some receivers and tools treat as line breaks.
    static func isForbiddenControlScalar(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value <= 0x1F || (0x7F...0x9F).contains(scalar.value) || scalar.value == 0x2028 || scalar.value == 0x2029
    }

    /// The single, uniformly-applied discipline for every caller-controlled
    /// string that ends up embedded raw into an RFC 5322 header line or an
    /// SMTP command line — routed through by every one of the call sites
    /// identified in the milestone review: `encodeAddress`'s addr-spec,
    /// `MIMEComposer`'s `extraHeaders` names (previously unchecked — the
    /// full-Bcc-injection bypass), `messageID`/`inReplyTo`/`references`,
    /// attachment/inline `Content-Type`, and `SMTPEnvelope`/`ReversePath`'s
    /// `MAIL FROM`/`RCPT TO` addr-specs. Throws (fail loud) rather than
    /// silently stripping, matching the existing `extraHeaders`-value
    /// precedent — a caller that manages to construct a string containing
    /// a control character here almost certainly has a bug worth
    /// surfacing, not silently "fixing".
    public static func rejectHeaderInjection(_ value: String, field: String) throws -> String {
        guard !value.unicodeScalars.contains(where: isForbiddenControlScalar) else {
            throw HeaderInjectionError.controlCharacterInField(field)
        }
        return value
    }

    /// Strips control characters (CR/LF and the rest of the C0 range, plus
    /// DEL) from free-text header input in place, to prevent header
    /// injection — a header value containing raw line breaks could
    /// otherwise be used to smuggle additional headers (or, in the worst
    /// case, a fake `Bcc:`) past the composer's denylist. Applied to
    /// Subject text and display-name phrases, where free-form user text is
    /// expected and silent stripping (rather than throwing) is the
    /// established, documented precedent for this specific pair of call
    /// sites (`encodeUnstructured`/`encodePhrase`) — everywhere else now
    /// routes through the fail-loud `rejectHeaderInjection` above instead.
    /// Originally CR/LF-only; broadened to the full C0 control-character
    /// range (milestone review finding — see `isForbiddenControlScalar`).
    private static func sanitizeForHeader(_ text: String) -> String {
        guard text.unicodeScalars.contains(where: isForbiddenControlScalar) else { return text }
        return String(String.UnicodeScalarView(text.unicodeScalars.filter { !isForbiddenControlScalar($0) }))
    }

    private static func longestUnbreakableRun(_ text: String) -> Int {
        var longest = 0, current = 0
        for byte in text.utf8 {
            if byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") { current = 0 } else { current += 1; longest = max(longest, current) }
        }
        return longest
    }

    private static func needsEncoding(_ text: String) -> Bool {
        !text.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }
    }

    private static func isPlainAtomsPhrase(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        if text.hasPrefix(" ") || text.hasSuffix(" ") { return false }
        if text.contains("  ") { return false }
        for ch in text where ch != " " {
            if !atextChars.contains(ch) { return false }
        }
        return true
    }

    private static func quotedString(_ text: String) -> String {
        var escaped = ""
        escaped.reserveCapacity(text.count + 2)
        for ch in text {
            if ch == "\"" || ch == "\\" { escaped.append("\\") }
            escaped.append(ch)
        }
        return "\"\(escaped)\""
    }

    /// Splits `text` into base64 RFC 2047 encoded-words, never splitting a
    /// Unicode scalar's UTF-8 byte sequence across two words: each scalar
    /// is checked whole against the remaining budget before being
    /// appended, so a chunk boundary can only ever fall between scalars.
    private static func encodedWords(for text: String) -> [String] {
        var words: [String] = []
        var currentBytes: [UInt8] = []
        currentBytes.reserveCapacity(maxPayloadBytesPerWord)

        func flush() {
            guard !currentBytes.isEmpty else { return }
            let b64 = Data(currentBytes).base64EncodedString()
            words.append("=?utf-8?B?\(b64)?=")
            currentBytes.removeAll(keepingCapacity: true)
        }

        for scalar in text.unicodeScalars {
            let scalarBytes = Array(String(scalar).utf8)
            if currentBytes.count + scalarBytes.count > maxPayloadBytesPerWord {
                flush()
            }
            currentBytes.append(contentsOf: scalarBytes)
        }
        flush()

        return words.isEmpty ? ["=?utf-8?B??="] : words
    }
}

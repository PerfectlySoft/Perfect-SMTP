//
//  SMTPEnvelope.swift
//  PerfectSMTPCore
//
//  See Documentation/swift6-nio-rewrite-plan.md §4.7.
//

/// `MAIL FROM` reverse-path. Modeled as an enum (not a plain `String`)
/// specifically so the RFC 5321 §4.5.5 null return-path required for
/// bounces/DSNs/auto-replies (`MAIL FROM:<>`) is representable and
/// guaranteed by the serializer — a plain `String` can neither represent
/// nor guarantee this (plan §4.7).
public enum ReversePath: Sendable, Hashable {
    /// `MAIL FROM:<address>`
    case address(String)
    /// `MAIL FROM:<>` — required for DSNs/bounces/auto-replies, RFC 5321 §4.5.5.
    case null

    /// The literal `MAIL FROM:<...>` command text. `.null` serializes to
    /// exactly `MAIL FROM:<>`.
    ///
    /// Milestone review finding (security pass): the `.address` case
    /// previously embedded `address` raw into the command line — SMTP
    /// **command** injection (RFC 5321 §4.1.2's `addr-spec` grammar
    /// forbids CR/LF in a mailbox), not just header injection, and reaches
    /// the wire once Phase 1 wires this envelope type into the real
    /// connection. Now routed through the same `rejectHeaderInjection`
    /// character-class check `HeaderEncoder` uses for RFC 5322 header
    /// lines — the character class that must never appear unescaped is
    /// identical even though this is a command line, not a header.
    /// `throws` (rather than silently stripping) for the same reason
    /// `HeaderEncoder.encodeAddress` throws: a mangled reverse-path
    /// address is a caller bug worth surfacing, not something to quietly
    /// "fix" into a different address.
    public var mailFromCommand: String {
        get throws {
            switch self {
            case .address(let address):
                let validated = try HeaderEncoder.rejectHeaderInjection(address, field: "MAIL FROM address")
                try Self.rejectLeadingHyphen(validated, field: "MAIL FROM address")
                try AddressSyntax.validateMailbox(validated, field: "MAIL FROM address")
                return "MAIL FROM:<\(validated)>"
            case .null:
                return "MAIL FROM:<>"
            }
        }
    }

    /// Milestone review finding (FIX #2, security pass, confirmed
    /// independently by three of the four reviews): `LocalMTATransport`
    /// passes this address to `sendmail`/Postfix/Exim as a bare `argv`
    /// element (via `-f`). `Process`'s array form avoids *shell* injection,
    /// but the local MTA's own `getopt`-style argv parser treats any
    /// argument starting with `-` as a command-line flag, not a literal
    /// address -- e.g. `-oQ/tmp/evilqueue@x` or `-C/tmp/attacker.cf` reach
    /// the subprocess's argv unmodified otherwise, the exact vulnerability
    /// class behind CVE-2016-10033/10045 (PHPMailer) and CVE-2016-10074
    /// (SwiftMailer). This is layer 1 of a two-layer defense-in-depth fix;
    /// layer 2 is `LocalMTATransport.runProcess` inserting a literal `"--"`
    /// end-of-options separator before the recipient list regardless.
    /// Deliberately narrow -- this checks only the leading character, not
    /// general RFC 5321 `addr-spec` grammar, matching Phase 0's established
    /// scoping discipline of staying narrow to injection-class defenses.
    static func rejectLeadingHyphen(_ address: String, field: String) throws {
        guard address.hasPrefix("-") else { return }
        throw HeaderEncoder.HeaderInjectionError.leadingHyphenInField(field)
    }
}

/// Delivery Status Notification request parameters (RFC 3461), carried on
/// `MAIL FROM`/`RCPT TO` as `RET`/`ENVID`/`NOTIFY`. Pure data in Phase 0 —
/// the transport that actually emits these ESMTP parameters is Phase 1.
public struct DSNRequest: Sendable, Hashable {
    public enum ReturnType: String, Sendable {
        case full = "FULL"
        case headers = "HDRS"
    }

    public enum NotifyOption: String, Sendable, CaseIterable {
        case never = "NEVER"
        case success = "SUCCESS"
        case failure = "FAILURE"
        case delay = "DELAY"
    }

    public var ret: ReturnType?
    public var envelopeID: String?
    public var notify: Set<NotifyOption>?

    public init(ret: ReturnType? = nil, envelopeID: String? = nil, notify: Set<NotifyOption>? = nil) {
        self.ret = ret
        self.envelopeID = envelopeID
        self.notify = notify
    }
}

/// The SMTP envelope — routing information that is entirely separate from
/// the composed message's headers. `recipients` is the *only* place a Bcc
/// address ever lives (the Bug #1 fix, plan §4.7): `to` + `cc` + Bcc
/// addr-specs, supplied by the caller, all end up here as plain strings
/// destined for individual `RCPT TO` commands — never serialized into any
/// header.
public struct SMTPEnvelope: Sendable {
    /// Validated by `init` (a plain mailbox with no leading `-`, or `.null`)
    /// and read-only afterwards. Release review: these used to be public
    /// `var`s, so a caller could swap in an unvalidated address after
    /// construction and `LocalMTATransport` passed it straight to the
    /// `sendmail` argv. Build a new envelope instead of mutating one.
    public private(set) var mailFrom: ReversePath
    /// Destined for individual `RCPT TO` commands (or the `sendmail` argv).
    /// Validated by `init` like `mailFrom` and read-only afterwards.
    public private(set) var recipients: [String]
    public var size: Int?
    public var dsn: DSNRequest?

    public init(mailFrom: ReversePath, recipients: [String], size: Int? = nil, dsn: DSNRequest? = nil) throws {
        try Self.validate(mailFrom: mailFrom, recipients: recipients)
        self.mailFrom = mailFrom
        self.recipients = recipients
        self.size = size
        self.dsn = dsn
    }

    /// Re-runs `init`'s checks. Transports call this right before an
    /// address reaches the wire or a command line (defense in depth).
    public func validate() throws {
        try Self.validate(mailFrom: mailFrom, recipients: recipients)
    }

    private static func validate(mailFrom: ReversePath, recipients: [String]) throws {
        _ = try mailFrom.mailFromCommand
        for recipient in recipients {
            _ = try HeaderEncoder.rejectHeaderInjection(recipient, field: "RCPT TO address")
            // FIX #2 (security review, CWE-88): reject a leading `-` here
            // too -- see `ReversePath.rejectLeadingHyphen`'s doc comment.
            // Recipients reach `LocalMTATransport`'s argv exactly the same
            // way the reverse-path address does.
            try ReversePath.rejectLeadingHyphen(recipient, field: "RCPT TO address")
            try AddressSyntax.validateMailbox(recipient, field: "RCPT TO address")
        }
    }
}

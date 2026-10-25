//
//  AddressSyntax.swift
//  PerfectSMTPCore
//
//  Release review: addresses used to be checked for control characters
//  only, so `victim@example.test> NOTIFY=SUCCESS ORCPT=rfc822;spoof@evil`
//  reached the wire as `RCPT TO:<victim@example.test> NOTIFY=... >` (ESMTP
//  parameter injection), and `s@example.test>, <attacker@evil.test` as a
//  From address added a second mailbox. Every address that goes into an
//  SMTP command or an address header now has to be a plain RFC 5321
//  mailbox, and every hostname an LDH name.
//

/// Syntax checks for mailboxes and hostnames.
///
/// A mailbox is accepted when it is `local-part@domain` with:
/// - a dot-atom local part (RFC 5322 `atext` and single interior dots), at
///   most 64 octets. Quoted local parts (`"john doe"@example.com`) are
///   rejected: they are vanishingly rare and the quoting is exactly where
///   `<`, `>` and spaces hide.
/// - a domain that is an LDH hostname (see `isHostname`) or an address
///   literal (`[192.0.2.1]`, `[IPv6:2001:db8::1]`).
/// - nothing else: no `<`, `>`, `"`, whitespace of any kind, or control
///   characters, and exactly one `@`.
///
/// Non-ASCII addresses are rejected. Sending them needs SMTPUTF8 (RFC 6531)
/// end to end, which this library doesn't implement yet; convert an
/// internationalized domain to its A-label (punycode) form before use.
public enum AddressSyntax {
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `field` holds something that isn't a plain mailbox.
        case invalidMailbox(field: String)
        /// `field` holds something that isn't an LDH hostname.
        case invalidHostname(field: String)
    }

    /// Throws `Error.invalidMailbox` unless `address` is a mailbox as
    /// described on `AddressSyntax`.
    public static func validateMailbox(_ address: String, field: String) throws {
        guard isMailbox(address) else { throw Error.invalidMailbox(field: field) }
    }

    /// Throws `Error.invalidHostname` unless `name` is an LDH hostname.
    public static func validateHostname(_ name: String, field: String) throws {
        guard isHostname(name) else { throw Error.invalidHostname(field: field) }
    }

    public static func isMailbox(_ address: String) -> Bool {
        let bytes = Array(address.utf8)
        // RFC 5321 §4.5.3.1.3: a path is at most 256 octets including the
        // angle brackets, so the address itself at most 254.
        guard bytes.count <= 254, bytes.allSatisfy({ $0 < 0x80 }) else { return false }
        let parts = bytes.split(separator: UInt8(ascii: "@"), omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        return isDotAtom(Array(parts[0])) && parts[0].count <= 64 && isDomainOrLiteral(Array(parts[1]))
    }

    /// An LDH hostname (RFC 1123 §2.1, RFC 5890 A-labels included): one or
    /// more dot-separated labels of 1–63 letters, digits and hyphens, not
    /// starting or ending with a hyphen, at most 253 octets in all, with no
    /// trailing dot. Single-label names (`localhost`) are accepted.
    public static func isHostname(_ name: String) -> Bool {
        isHostname(Array(name.utf8))
    }

    static func isHostname(_ bytes: [UInt8]) -> Bool {
        guard !bytes.isEmpty, bytes.count <= 253 else { return false }
        let labels = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            guard (1...63).contains(label.count),
                  label.first != UInt8(ascii: "-"), label.last != UInt8(ascii: "-")
            else { return false }
            return label.allSatisfy { isLetterOrDigit($0) || $0 == UInt8(ascii: "-") }
        }
    }

    /// An LDH hostname or an address literal (`[192.0.2.1]`) -- what RFC
    /// 5321 allows as the EHLO argument.
    public static func isHostnameOrAddressLiteral(_ name: String) -> Bool {
        isDomainOrLiteral(Array(name.utf8))
    }

    private static func isDomainOrLiteral(_ bytes: [UInt8]) -> Bool {
        if bytes.first == UInt8(ascii: "[") {
            guard bytes.count > 2, bytes.last == UInt8(ascii: "]") else { return false }
            return isAddressLiteral(String(decoding: bytes.dropFirst().dropLast(), as: UTF8.self))
        }
        return isHostname(bytes)
    }

    /// RFC 5321 §4.1.3: an IPv4 dotted quad, or `IPv6:` (any case)
    /// followed by an IPv6 address in RFC 4291 §2.2 text form.
    private static func isAddressLiteral(_ text: String) -> Bool {
        if text.utf8.count > 5, text.prefix(5).lowercased() == "ipv6:" {
            return isIPv6(String(text.dropFirst(5)))
        }
        return isIPv4(text)
    }

    static func isIPv4(_ text: String) -> Bool {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        return octets.count == 4 && octets.allSatisfy { octet in
            (1...3).contains(octet.count) && octet.utf8.allSatisfy(isDigit) && Int(octet).map { $0 <= 255 } == true
        }
    }

    /// Eight 1–4 digit hex groups, or fewer with exactly one `::`
    /// standing for one or more zero groups; the last 32 bits may be a
    /// dotted quad. `::::`, `1::2::3`, `12345::` and similar are refused.
    static func isIPv6(_ text: String) -> Bool {
        guard !text.isEmpty, text.utf8.count <= 45 else { return false }
        let halves = text.components(separatedBy: "::")
        guard halves.count <= 2 else { return false }
        func groups(_ part: String, allowIPv4Tail: Bool) -> Int? {
            if part.isEmpty { return 0 }
            let pieces = part.split(separator: ":", omittingEmptySubsequences: false)
            var count = 0
            for (index, piece) in pieces.enumerated() {
                if allowIPv4Tail, index == pieces.count - 1, piece.contains(".") {
                    guard isIPv4(String(piece)) else { return nil }
                    count += 2
                } else {
                    guard (1...4).contains(piece.count), piece.utf8.allSatisfy(isHexDigit) else { return nil }
                    count += 1
                }
            }
            return count
        }
        if halves.count == 1 {
            return groups(halves[0], allowIPv4Tail: true) == 8
        }
        guard let head = groups(halves[0], allowIPv4Tail: false), let tail = groups(halves[1], allowIPv4Tail: true) else { return false }
        return head + tail <= 7
    }

    private static func isDotAtom(_ bytes: [UInt8]) -> Bool {
        guard !bytes.isEmpty else { return false }
        let atoms = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        return atoms.allSatisfy { atom in !atom.isEmpty && atom.allSatisfy(isAtext) }
    }

    /// RFC 5322 §3.2.3 `atext`.
    private static func isAtext(_ byte: UInt8) -> Bool {
        isLetterOrDigit(byte) || "!#$%&'*+-/=?^_`{|}~".utf8.contains(byte)
    }

    private static func isLetterOrDigit(_ byte: UInt8) -> Bool {
        isDigit(byte) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        isDigit(byte) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
    }
}

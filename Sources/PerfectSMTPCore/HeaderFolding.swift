//
//  HeaderFolding.swift
//  PerfectSMTPCore
//
//  Release review: header values were emitted on one line however long
//  they got (200 To addresses, 100 References, the DKIM-Signature's h= and
//  b=). RFC 5322 §2.1.1 caps a line at 998 octets (MUST) and recommends 78
//  (SHOULD); many receivers reject or truncate longer lines.
//

/// RFC 5322 §2.2.3 folding: inserting CRLF before existing whitespace.
public enum HeaderFolding {
    /// The SHOULD limit of RFC 5322 §2.1.1, excluding the CRLF.
    public static let recommendedLineLength = 78
    /// The MUST limit of RFC 5322 §2.1.1, excluding the CRLF.
    public static let maximumLineLength = 998

    /// Folds `value` so that, written as `name: value`, each physical line
    /// is at most `recommendedLineLength` octets wherever a break point
    /// allows. Break points are the space or tab characters already in the
    /// value (the whitespace starts the continuation line); characters in
    /// `insertingBreaksAfter` additionally allow a fold to be inserted
    /// right after them (`"\r\n "`), for structured values whose grammar
    /// permits FWS there (the DKIM-Signature tag list). Existing folds are
    /// kept, so folding is idempotent.
    public static func fold(name: String, value: String, insertingBreaksAfter: Set<UInt8> = []) -> String {
        let space = UInt8(ascii: " "), tab = UInt8(ascii: "\t"), cr = UInt8(ascii: "\r"), lf = UInt8(ascii: "\n")
        let bytes = Array(value.utf8)
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count + bytes.count / 60 * 3)
        var lineLength = name.utf8.count + 2 // "name: "
        // Index in `output` of the latest break opportunity on the current
        // line, and whether it's a WSP (fold before it) or an insertion
        // point (fold after the character, adding a space).
        var lastBreak: (index: Int, inserting: Bool)?

        var i = 0
        while i < bytes.count {
            let byte = bytes[i]
            if byte == cr, i + 1 < bytes.count, bytes[i + 1] == lf {
                // An existing fold: keep it and start a new line.
                output.append(cr); output.append(lf)
                i += 2
                lineLength = 0
                lastBreak = nil
                continue
            }
            if (byte == space || byte == tab), lineLength > 0 {
                lastBreak = (output.count, false)
            }
            output.append(byte)
            lineLength += 1
            if insertingBreaksAfter.contains(byte) {
                lastBreak = (output.count, true)
            }
            if lineLength > recommendedLineLength, let point = lastBreak, point.index < output.count {
                let fold: [UInt8] = point.inserting ? [cr, lf, space] : [cr, lf]
                output.insert(contentsOf: fold, at: point.index)
                lineLength = output.count - point.index - 2
                lastBreak = nil
            }
            i += 1
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// The longest physical line `name: value` produces, in octets.
    public static func longestLine(name: String, value: String) -> Int {
        let lines = "\(name): \(value)".utf8.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: false)
        return lines.map { $0.last == UInt8(ascii: "\r") ? $0.count - 1 : $0.count }.max() ?? 0
    }
}

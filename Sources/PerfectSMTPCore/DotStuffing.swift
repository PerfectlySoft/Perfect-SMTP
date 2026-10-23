//
//  DotStuffing.swift
//  PerfectSMTPCore
//
//  RFC 5321 §4.5.2 transparency: any line beginning with '.' has that dot
//  doubled before transmission, and the DATA phase is terminated by a
//  line consisting of a single '.' followed by CRLF. This is a
//  wire-transparency mechanism the receiver reverses before further
//  processing — it is applied to (and is orthogonal to) an already-signed
//  message; DKIM canonicalization operates on the logical message, dot-
//  stuffing on the wire form (plan §4.6).
//

public enum DotStuffing {
    /// Normalizes line endings, dot-stuffs, and appends the terminator.
    ///
    /// Release review: every bare CR and bare LF is turned into CRLF first.
    /// Composed messages already use CRLF throughout, but a raw
    /// `SignedMessage` could carry `x\r.\r\nMAIL FROM:...`; a lone CR is
    /// never a line start here, so its dot was not stuffed, and receivers
    /// that treat a bare CR or LF as a line break would see an early end
    /// of data followed by smuggled commands (the 2023 SMTP-smuggling
    /// class). After normalization every line break is CRLF, so the only
    /// `CRLF.CRLF` on the wire is the terminator.
    public static func encode(_ message: [UInt8]) -> [UInt8] {
        let dot: UInt8 = 0x2E
        let cr: UInt8 = 0x0D
        let lf: UInt8 = 0x0A

        var output = [UInt8]()
        output.reserveCapacity(message.count + 8)

        var atLineStart = true
        var index = 0
        while index < message.count {
            let byte = message[index]
            if byte == cr || byte == lf {
                // CRLF, bare CR and bare LF all become one CRLF.
                output.append(cr)
                output.append(lf)
                index += (byte == cr && index + 1 < message.count && message[index + 1] == lf) ? 2 : 1
                atLineStart = true
                continue
            }
            if atLineStart && byte == dot {
                output.append(dot)
            }
            output.append(byte)
            atLineStart = false
            index += 1
        }

        if !(output.count >= 2 && output[output.count - 2] == cr && output[output.count - 1] == lf) {
            output.append(cr)
            output.append(lf)
        }
        output.append(dot)
        output.append(cr)
        output.append(lf)
        return output
    }
}

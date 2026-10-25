//
//  DotStuffingTests.swift
//  PerfectSMTPCoreTests
//
//  RFC 5321 §4.5.2 transparency: leading-dot doubling, terminal `.\r\n`.
//

import Testing
@testable import PerfectSMTPCore

struct DotStuffingTests {

    @Test func doublesLeadingDotsAndAppendsTerminator() {
        let input = Array("Hello\r\n.World\r\n..Test\r\nEnd".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n..World\r\n...Test\r\nEnd\r\n.\r\n")
    }

    @Test func doesNotTouchDotsNotAtLineStart() {
        let input = Array("a.b.c\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "a.b.c\r\n.\r\n")
    }

    @Test func doesNotDoubleTrailingCRLFBeforeTerminator() {
        let input = Array("Hello\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n.\r\n")
    }

    @Test func addsMissingTrailingCRLFBeforeTerminator() {
        let input = Array("Hello".utf8) // no trailing CRLF at all
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n.\r\n")
    }

    @Test func onlyLeadingDotOfEachLineIsDoubledNotEveryDot() {
        let input = Array(".a.b.c\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "..a.b.c\r\n.\r\n")
    }
}

/// Release review: bare CR and bare LF on the raw `SignedMessage` path.
struct DotStuffingLineEndingTests {
    private static func onlyCRLF(_ bytes: [UInt8]) -> Bool {
        for i in bytes.indices {
            if bytes[i] == 0x0D, i + 1 >= bytes.count || bytes[i + 1] != 0x0A { return false }
            if bytes[i] == 0x0A, i == 0 || bytes[i - 1] != 0x0D { return false }
        }
        return true
    }

    @Test(arguments: [
        ("A\r\n\r\nx\r.\r\nMAIL FROM:<a@b>\r\n", "A\r\n\r\nx\r\n..\r\nMAIL FROM:<a@b>\r\n.\r\n"),
        ("A\r\n\r\nx\n.\nMAIL\r\n", "A\r\n\r\nx\r\n..\r\nMAIL\r\n.\r\n"),
        ("A\r\n\r\nx\n.\r\nMAIL\r\n", "A\r\n\r\nx\r\n..\r\nMAIL\r\n.\r\n"),
        ("x\r\n.\rRSET", "x\r\n..\r\nRSET\r\n.\r\n"),
        ("\r.\r", "\r\n..\r\n.\r\n"),
        ("a\r\r\nb", "a\r\n\r\nb\r\n.\r\n"),
    ])
    func bareLineEndingsBecomeCRLFBeforeStuffing(input: String, expected: String) {
        let wire = DotStuffing.encode(Array(input.utf8))
        #expect(String(decoding: wire, as: UTF8.self) == expected)
        #expect(Self.onlyCRLF(wire))
        // The terminator is the only CRLF.CRLF.
        let text = String(decoding: wire, as: UTF8.self)
        #expect(text.components(separatedBy: "\r\n.\r\n").count == 2)
    }
}

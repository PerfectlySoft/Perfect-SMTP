//
//  HeaderFoldingTests.swift
//  PerfectSMTPCoreTests
//
//  Release review: long headers (200 To addresses, 100 References, a
//  2000-character subject, the DKIM-Signature) used to go out on one line,
//  past RFC 5322's 998-octet limit.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct HeaderFoldingTests {
    private static func longestHeaderLine(_ message: RFC5322Message) -> Int {
        let text = String(decoding: message.serialized(), as: UTF8.self)
        let header = text.components(separatedBy: "\r\n\r\n")[0]
        return header.components(separatedBy: "\r\n").map(\.utf8.count).max() ?? 0
    }

    private static func base() -> EmailMessage {
        var message = EmailMessage(from: EmailAddress(displayName: "Sender", address: "sender@example.test"))
        message.to = [EmailAddress(address: "rcpt@example.test")]
        message.textBody = "hello"
        return message
    }

    @Test func foldingBreaksBeforeWhitespaceAndIsIdempotent() {
        let value = (0..<40).map { "word\($0)" }.joined(separator: " ")
        let folded = HeaderFolding.fold(name: "X-Long", value: value)
        #expect(HeaderFolding.longestLine(name: "X-Long", value: folded) <= 78)
        #expect(folded.replacingOccurrences(of: "\r\n", with: "") == value)
        #expect(HeaderFolding.fold(name: "X-Long", value: folded) == folded)
    }

    @Test func manyRecipientsAndReferencesFoldUnder78() throws {
        var message = Self.base()
        message.to = (0..<200).map { EmailAddress(displayName: "User \($0)", address: "user\($0)@example.test") }
        message.cc = (0..<50).map { EmailAddress(address: "cc\($0)@example.test") }
        message.references = (0..<100).map { _ in "<\(UUID().uuidString)@example.test>" }
        let composed = try MIMEComposer(message).compose()
        #expect(Self.longestHeaderLine(composed) <= 78)
        // Unfolding gives back every address.
        let to = try #require(composed.headers.first { $0.name == "To" }?.value).replacingOccurrences(of: "\r\n", with: "")
        #expect(to.components(separatedBy: ", ").count == 200)
    }

    @Test func aLongUnbrokenSubjectIsEncodedSoItCanBeFolded() throws {
        var message = Self.base()
        message.subject = String(repeating: "A", count: 2000)
        let composed = try MIMEComposer(message).compose()
        #expect(Self.longestHeaderLine(composed) <= 78)
    }

    @Test func anUnfoldableExtraHeaderIsRejected() {
        var message = Self.base()
        message.extraHeaders = [("X-Token", String(repeating: "x", count: 1200))]
        #expect(throws: MIMEComposer.ComposerError.headerLineTooLong("X-Token")) { _ = try MIMEComposer(message).compose() }
    }

    @Test func theDKIMSignatureHeaderIsFolded() throws {
        var message = Self.base()
        message.subject = "Folded DKIM"
        let signer = try DKIMSigner(
            domain: "example.test", selector: "sel",
            signedHeaders: ["from", "to", "subject", "date", "message-id", "mime-version", "content-type", "reply-to", "cc"],
            keys: [try SigningKey.ed25519(rawRepresentation: Data(repeating: 7, count: 32))]
        )
        let signed = try signer.sign(try MIMEComposer(message).compose())
        #expect(Self.longestHeaderLine(signed) <= 78)
    }
}

/// Release review: folding before trailing whitespace made a continuation
/// line of only whitespace.
struct HeaderFoldingWhitespaceTests {
    private static func lines(_ name: String, _ value: String) -> [String] {
        "\(name): \(HeaderFolding.fold(name: name, value: value))".components(separatedBy: "\r\n")
    }

    @Test(arguments: [
        String(repeating: "L", count: 70) + "a(c)end ",
        String(repeating: "L", count: 70) + "a(c)end    ",
        String(repeating: "word ", count: 40),
        String(repeating: "x", count: 77) + " \t ",
        "a" + String(repeating: " ", count: 120),
    ])
    func noContinuationLineIsOnlyWhitespace(value: String) {
        let folded = Self.lines("Subject", value)
        #expect(!folded.dropFirst().contains { $0.allSatisfy { $0 == " " || $0 == "\t" } }, "\(folded)")
        #expect(folded.joined() == "Subject: \(value)")
    }

    @Test func theReviewersSubjectComposesWithoutAWhitespaceLine() throws {
        var message = EmailMessage(from: EmailAddress(address: "sender@example.test"))
        message.to = [EmailAddress(address: "rcpt@example.test")]
        message.subject = String(repeating: "L", count: 70) + "a(c)end "
        message.textBody = "hi"
        let header = String(decoding: try MIMEComposer(message).compose().serialized(), as: UTF8.self).components(separatedBy: "\r\n\r\n")[0]
        #expect(!header.components(separatedBy: "\r\n").contains { !$0.isEmpty && $0.allSatisfy { $0 == " " || $0 == "\t" } })
    }
}

/// Release review nit: ASCII text containing "=?" is encoded, so a
/// lookalike encoded word isn't decoded by the receiver.
struct LookalikeEncodedWordTests {
    @Test func subjectsAndDisplayNamesWithEqualsQuestionAreEncoded() {
        let subject = HeaderEncoder.encodeUnstructured("price =?utf-8?q?FREE?= today")
        #expect(subject.hasPrefix("=?utf-8?B?"))
        let phrase = HeaderEncoder.encodePhrase("=?utf-8?q?Admin?=")
        #expect(phrase.hasPrefix("=?utf-8?B?"))
        #expect(HeaderEncoder.encodeUnstructured("plain = and ? apart") == "plain = and ? apart")
    }
}

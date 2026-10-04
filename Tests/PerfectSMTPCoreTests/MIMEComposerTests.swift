//
//  MIMEComposerTests.swift
//  PerfectSMTPCoreTests
//
//  Golden fixtures for the multipart shape from plan §4.7:
//    multipart/mixed [ multipart/related [ multipart/alternative [
//      text/plain, text/html ], inline CID images ], attachments ]
//  with empty layers collapsed.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

private let fixedDate = Date(timeIntervalSince1970: 1_700_000_000) // 2023-11-14T22:13:20Z

struct MIMEComposerTests {

    // MARK: - Golden fixture: single leaf (no alternative/related/mixed)

    @Test func singlePlainTextBodyIsNotWrappedInAnyMultipart() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Hello"
        message.textBody = "hello world"
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
        #expect(String(decoding: composed.body, as: UTF8.self) == "hello world")
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart"))
    }

    // MARK: - Golden fixture: multipart/alternative only

    @Test func textAndHtmlBodyProducesExactAlternativeStructure() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Hello"
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["ALT"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()

        #expect(header(composed, "Content-Type") == "multipart/alternative; boundary=\"ALT\"")

        let expectedBody =
            "--ALT\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "hello\r\n" +
            "--ALT\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "<p>hello</p>\r\n" +
            "--ALT--\r\n"
        #expect(String(decoding: composed.body, as: UTF8.self) == expectedBody)
    }

    // MARK: - Golden fixture: multipart/mixed with a single body + one attachment (no related)

    @Test func textBodyPlusAttachmentProducesExactMixedStructureWithNoRelated() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8))]
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["MIX"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()

        #expect(header(composed, "Content-Type") == "multipart/mixed; boundary=\"MIX\"")

        let expectedBody =
            "--MIX\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "hi\r\n" +
            "--MIX\r\n" +
            "Content-Type: text/plain; name=\"a.txt\"\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "Content-Disposition: attachment; filename=\"a.txt\"\r\n\r\n" +
            "aGk=\r\n" +
            "--MIX--\r\n"
        #expect(String(decoding: composed.body, as: UTF8.self) == expectedBody)
        // No related layer since there are no inline images.
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart/related"))
    }

    // MARK: - Golden fixture: full nesting, mixed[related[alternative[...],inline],attachments]

    @Test func fullNestingProducesMixedContainingRelatedContainingAlternative() throws {
        var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Test"
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.inlineImages = [
            InlineResource(contentID: "img1", contentType: "image/png", data: Data([0, 1, 2])),
        ]
        message.attachments = [
            Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8)),
        ]
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["ALT", "REL", "MIX"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()
        let body = String(decoding: composed.body, as: UTF8.self)

        #expect(header(composed, "Content-Type") == "multipart/mixed; boundary=\"MIX\"")

        // Structural nesting order: MIX opens, then REL nested inside it,
        // then ALT nested inside REL, then the inline image inside REL
        // (after the alternative), then the attachment inside MIX (after
        // the related group), then both closing boundaries in the right
        // order.
        let mixOpen = try #require(body.range(of: "--MIX\r\n"))
        let relatedHeader = try #require(body.range(of: "Content-Type: multipart/related; boundary=\"REL\""))
        let altHeader = try #require(body.range(of: "Content-Type: multipart/alternative; boundary=\"ALT\""))
        let altClose = try #require(body.range(of: "--ALT--\r\n"))
        let inlineID = try #require(body.range(of: "Content-ID: <img1>"))
        let relClose = try #require(body.range(of: "--REL--\r\n"))
        let attachmentDisposition = try #require(body.range(of: "Content-Disposition: attachment; filename=\"a.txt\""))
        let mixClose = try #require(body.range(of: "--MIX--\r\n"))

        #expect(mixOpen.lowerBound < relatedHeader.lowerBound)
        #expect(relatedHeader.lowerBound < altHeader.lowerBound)
        #expect(altHeader.lowerBound < altClose.lowerBound)
        #expect(altClose.lowerBound < inlineID.lowerBound)
        #expect(inlineID.lowerBound < relClose.lowerBound)
        #expect(relClose.lowerBound < attachmentDisposition.lowerBound)
        #expect(attachmentDisposition.lowerBound < mixClose.lowerBound)

        #expect(body.contains("hello"))
        #expect(body.contains("<p>hello</p>"))
        #expect(body.contains("AAEC")) // base64 of the inline image bytes [0,1,2]
        #expect(body.contains("aGk=")) // base64 of the attachment "hi"
    }

    // MARK: - Layer collapsing

    @Test func noInlineImagesDropsRelatedLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.attachments = [Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8))]

        let composed = try MIMEComposer(message).compose()
        let body = String(decoding: composed.body, as: UTF8.self)
        #expect(!body.contains("multipart/related"))
        #expect(body.contains("multipart/alternative"))
    }

    @Test func noAttachmentsDropsMixedLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.inlineImages = [InlineResource(contentID: "img1", contentType: "image/png", data: Data([0, 1]))]

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Type")?.hasPrefix("multipart/related") == true)
        let body = String(decoding: composed.body, as: UTF8.self)
        #expect(!body.contains("multipart/mixed"))
    }

    @Test func singleBodyDropsAlternativeLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello only"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart"))
    }

    // MARK: - Non-ASCII body uses quoted-printable, ASCII uses 7bit

    @Test func nonASCIITextBodyUsesQuotedPrintable() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
        #expect(String(decoding: composed.body, as: UTF8.self) == "Caf=C3=A9")
    }

    // MARK: - Date / Message-ID auto-synthesis

    @Test func dateAndMessageIDAreAutoSynthesizedWhenNil() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        // date/messageID intentionally left nil.

        let composed = try MIMEComposer(message).compose()
        let dateHeader = try #require(header(composed, "Date"))
        let messageIDHeader = try #require(header(composed, "Message-ID"))

        #expect(!dateHeader.isEmpty)
        #expect(messageIDHeader.hasPrefix("<"))
        #expect(messageIDHeader.hasSuffix("@example.com>")) // scoped to from's domain, see doc comment
    }

    @Test func explicitDateAndMessageIDAreNotOverwritten() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.date = fixedDate
        message.messageID = "<explicit-id@caller.example>"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Message-ID") == "<explicit-id@caller.example>")
        #expect(header(composed, "Date") == MIMEComposer.rfc5322DateString(fixedDate))
    }

    // MARK: - Validation errors

    @Test func missingBodyThrows() {
        let message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        #expect(throws: MIMEComposer.ComposerError.missingBody) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func headerValueWithEmbeddedNewlineThrows() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.extraHeaders = [("X-Custom", "line1\nline2")]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("X-Custom")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - Milestone review finding #7: path traversal in filenames

    @Test func pathTraversalAttachmentFilenameDoesNotSurviveIntoContentDisposition() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [
            Attachment(filename: "../../../../etc/passwd", contentType: "text/plain", data: Data("hi".utf8)),
        ]

        let composed = try MIMEComposer(message).compose()
        let body = String(decoding: composed.body, as: UTF8.self)

        #expect(!body.contains(".."))
        #expect(!body.contains("/etc/passwd"))
        #expect(body.contains("filename=\"passwd\""))
    }

    @Test func pathTraversalInlineResourceFilenameDoesNotSurviveIntoContentDisposition() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.inlineImages = [
            InlineResource(
                contentID: "img1",
                filename: "..\\..\\windows\\win.ini",
                contentType: "image/png",
                data: Data([0, 1, 2])
            ),
        ]

        let composed = try MIMEComposer(message).compose()
        let body = String(decoding: composed.body, as: UTF8.self)

        #expect(!body.contains(".."))
        #expect(!body.contains("windows\\win.ini"))
        #expect(body.contains("filename=\"win.ini\""))
    }

    @Test func leadingSlashFilenameIsBasenamed() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [
            Attachment(filename: "/etc/passwd", contentType: "text/plain", data: Data("hi".utf8)),
        ]

        let composed = try MIMEComposer(message).compose()
        let body = String(decoding: composed.body, as: UTF8.self)
        #expect(body.contains("filename=\"passwd\""))
        #expect(!body.contains("/etc/passwd"))
    }

    // MARK: - bodyContentTypeOverride / bodyTransferEncodingOverride (Lasso -contentType/-transferEncoding)
    //
    // Added for the LassoPerfectSMTP integration's legacy dash-params.
    // Both fields default to nil and are additive/opt-in -- see
    // `bodyOverrideFieldsNilProducesUnchangedSingleLeafOutput` for the
    // regression proof that leaving them unset doesn't change existing
    // behavior at all, plus the full pre-existing golden-fixture tests above
    // (none of which set either field) continuing to pass unchanged.

    @Test func bodyOverrideFieldsNilProducesUnchangedSingleLeafOutput() throws {
        // Byte-for-byte identical assertions to
        // `singlePlainTextBodyIsNotWrappedInAnyMultipart` above, just with
        // both new fields explicitly (redundantly) left at their nil
        // default, to document that this is the additive/opt-in
        // no-override case.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Hello"
        message.textBody = "hello world"
        message.bodyContentTypeOverride = nil
        message.bodyTransferEncodingOverride = nil
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
        #expect(String(decoding: composed.body, as: UTF8.self) == "hello world")
    }

    @Test func bodyContentTypeOverrideIsEmittedVerbatimAsBodyContentType() throws {
        // Milestone review fix: a non-UTF-8 `charset=` in the override now
        // throws (see the `bodyContentTypeOverrideCharsetMustBeUTF8...`
        // tests below), so this "emitted verbatim" test uses a UTF-8
        // charset -- still exercising verbatim emission of the rest of the
        // override string (the `text/x-legacy` subtype), just not the
        // now-rejected non-UTF-8 charset value the original version of this
        // test used.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyContentTypeOverride = "text/x-legacy; charset=UTF-8"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/x-legacy; charset=UTF-8")
        // Transfer-encoding is untouched by a content-type-only override --
        // still auto-computed (ASCII body -> 7bit).
        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
    }

    // MARK: - bodyContentTypeOverride charset=UTF-8 validation
    // (milestone review, FIX #1 -- architecture + protocol passes,
    // independently found: `bodyContentTypeOverride`'s declared charset was
    // never honored by the actual byte encoding, since this library has no
    // transcoding engine. See `EmailMessage.bodyContentTypeOverride`'s doc
    // comment for the full "no-transcoding" invariant this validates.)

    @Test func bodyContentTypeOverrideNonUTF8CharsetThrowsEvenWithASCIIBody() {
        // ASCII is byte-identical across charsets, so an ASCII body can't
        // itself reveal a charset mismatch -- this is exactly the
        // originally-untested gap the milestone review flagged. The
        // validation fires on the declared charset alone, regardless of
        // whether the current body content would actually be corrupted by
        // it.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyContentTypeOverride = "text/plain; charset=iso-8859-1"

        #expect(throws: MIMEComposer.ComposerError.bodyContentTypeOverrideCharsetMustBeUTF8) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyContentTypeOverrideNonUTF8CharsetThrowsWithNonASCIIBody() {
        // The realistic corruption scenario the review described: a
        // non-ASCII body whose wire bytes are (as always in this library)
        // UTF-8, paired with a declared charset that claims otherwise.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"
        message.bodyContentTypeOverride = "text/plain; charset=iso-8859-1"

        #expect(throws: MIMEComposer.ComposerError.bodyContentTypeOverrideCharsetMustBeUTF8) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyContentTypeOverrideQuotedNonUTF8CharsetThrows() {
        // Tolerant parsing also catches the quoted-value form.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyContentTypeOverride = "text/plain; charset=\"windows-1252\""

        #expect(throws: MIMEComposer.ComposerError.bodyContentTypeOverrideCharsetMustBeUTF8) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyContentTypeOverrideUTF8CharsetSucceeds() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"
        message.bodyContentTypeOverride = "text/plain; charset=utf-8"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
    }

    @Test func bodyContentTypeOverrideUTF8AliasCharsetSucceeds() throws {
        // "utf8" (no hyphen) is tolerated as a common alias.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"
        message.bodyContentTypeOverride = "text/plain; charset=utf8"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/plain; charset=utf8")
    }

    @Test func bodyContentTypeOverrideWithNoCharsetParameterSucceeds() throws {
        // No charset= parameter at all is not an error -- only a
        // present-and-non-UTF-8 value is rejected.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyContentTypeOverride = "application/x-legacy"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "application/x-legacy")
    }

    @Test func bodyTransferEncodingOverrideSevenBitWithASCIIBodySucceeds() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyTransferEncodingOverride = .sevenBit

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
        #expect(String(decoding: composed.body, as: UTF8.self) == "hello world")
    }

    @Test func bodyTransferEncodingOverrideSevenBitWithNonASCIIBodyThrowsAndDoesNotEmit7bit() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}" // contains a byte >= 0x80 in UTF-8
        message.bodyTransferEncodingOverride = .sevenBit

        #expect(throws: MIMEComposer.ComposerError.sevenBitOverrideRequiresValidSevenBitBody) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - .sevenBit validation against RFC 2045 §2.7's full definition
    // (milestone review, FIX #2 -- protocol pass: the original check only
    // covered the byte-range half of "7bit data"; NUL octets and overlong
    // lines were both silently unchecked.)

    @Test func bodyTransferEncodingOverrideSevenBitWithEmbeddedNULThrows() {
        // RFC 2045 §2.7: "No octets with decimal values greater than 127
        // are allowed and neither are NULs (octets with decimal value 0)."
        // A NUL byte is < 0x80, so the original (byte-range-only) check
        // passed this straight through as "7bit" -- the exact gap this fix
        // closes.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello\u{0}world"
        message.bodyTransferEncodingOverride = .sevenBit

        #expect(throws: MIMEComposer.ComposerError.sevenBitOverrideRequiresValidSevenBitBody) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyTransferEncodingOverrideSevenBitWithLineOver998OctetsThrows() {
        // RFC 2045 §2.7: "short lines with 998 octets or less between CRLF
        // line separation sequences." One line of 999 'a's, with a short
        // line on either side so only the middle line is actually overlong.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        let overlongLine = String(repeating: "a", count: 999)
        message.textBody = "first\n\(overlongLine)\nlast"
        message.bodyTransferEncodingOverride = .sevenBit

        #expect(throws: MIMEComposer.ComposerError.sevenBitOverrideRequiresValidSevenBitBody) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyTransferEncodingOverrideSevenBitWithLineOf998OctetsSucceeds() throws {
        // Exactly 998 octets is the boundary RFC 2045 §2.7 allows ("998
        // octets or less") -- must not throw.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        let boundaryLine = String(repeating: "a", count: 998)
        message.textBody = boundaryLine
        message.bodyTransferEncodingOverride = .sevenBit

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
    }

    @Test func defaultAutoDetectionFallsBackToQuotedPrintableForASCIIBodyWithEmbeddedNUL() throws {
        // Milestone review: the same NUL gap existed (pre-existing, not new
        // to this feature) in the default auto-detection path (no
        // override) -- fixed identically for consistency. An all-ASCII body
        // containing a NUL is no longer mislabeled `7bit`; it now falls
        // through to the same quoted-printable path a non-ASCII body uses.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello\u{0}world"
        // bodyTransferEncodingOverride left nil -- exercising auto-detection.

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
        #expect(String(decoding: composed.body, as: UTF8.self) == Encoders.quotedPrintable("hello\u{0}world"))
    }

    @Test func defaultAutoDetectionFallsBackToQuotedPrintableForASCIIBodyWithOverlongLine() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        let overlongLine = String(repeating: "a", count: 999)
        message.textBody = overlongLine
        // bodyTransferEncodingOverride left nil -- exercising auto-detection.

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
    }

    @Test func bodyTransferEncodingOverrideQuotedPrintableActuallyEncodesASCIIBody() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "100% = great"
        message.bodyTransferEncodingOverride = .quotedPrintable

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
        // Genuinely quoted-printable-encoded, not just labeled: '=' and the
        // '%' sign are escaped by the real QP transform.
        #expect(String(decoding: composed.body, as: UTF8.self) == Encoders.quotedPrintable("100% = great"))
        #expect(String(decoding: composed.body, as: UTF8.self).contains("=3D"))
    }

    @Test func bodyTransferEncodingOverrideQuotedPrintableActuallyEncodesNonASCIIBody() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"
        message.bodyTransferEncodingOverride = .quotedPrintable

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
        #expect(String(decoding: composed.body, as: UTF8.self) == "Caf=C3=A9")
    }

    @Test func bodyTransferEncodingOverrideBase64ActuallyEncodesASCIIBody() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyTransferEncodingOverride = .base64

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "base64")
        let bodyString = String(decoding: composed.body, as: UTF8.self)
        // Genuinely base64-encoded, not just labeled: decoding it round-trips
        // to the original CRLF-normalized text, and the raw plaintext never
        // appears in the wire bytes.
        #expect(!bodyString.contains("hello world"))
        let decoded = try #require(Data(base64Encoded: bodyString.replacingOccurrences(of: "\r\n", with: "")))
        #expect(String(decoding: decoded, as: UTF8.self) == "hello world")
    }

    @Test func bodyTransferEncodingOverrideBase64ActuallyEncodesNonASCIIBody() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"
        message.bodyTransferEncodingOverride = .base64

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Transfer-Encoding") == "base64")
        let bodyString = String(decoding: composed.body, as: UTF8.self)
        let decoded = try #require(Data(base64Encoded: bodyString.replacingOccurrences(of: "\r\n", with: "")))
        #expect(String(decoding: decoded, as: UTF8.self) == "Caf\u{e9}")
    }

    @Test func bothOverridesTogetherAreBothAppliedToTheSameSingleLeaf() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello world"
        message.bodyContentTypeOverride = "application/x-legacy"
        message.bodyTransferEncodingOverride = .base64

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "application/x-legacy")
        #expect(header(composed, "Content-Transfer-Encoding") == "base64")
    }

    @Test func bodyContentTypeOverrideWithBothTextAndHTMLBodiesThrows() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.bodyContentTypeOverride = "text/x-legacy"

        #expect(throws: MIMEComposer.ComposerError.bodyOverrideRequiresSingleBodyPart) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bodyTransferEncodingOverrideWithBothTextAndHTMLBodiesThrows() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.bodyTransferEncodingOverride = .sevenBit

        #expect(throws: MIMEComposer.ComposerError.bodyOverrideRequiresSingleBodyPart) {
            _ = try MIMEComposer(message).compose()
        }
    }
}

private func header(_ message: RFC5322Message, _ name: String) -> String? {
    message.headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
}

/// Non-ASCII attachment and inline-resource names (issue #21): RFC 2231 `filename*` on
/// Content-Disposition, RFC 2047 encoded-words in Content-Type `name`, no ASCII fallback.
struct RFC2231FilenameTests {
    private func composedBody(attachmentName: String) throws -> String {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [Attachment(filename: attachmentName, contentType: "application/pdf", data: Data("x".utf8))]
        return String(decoding: try MIMEComposer(message).compose().body, as: UTF8.self)
    }

    /// The header block (all lines, unfolded=false) of the attachment part.
    private func attachmentHeaderLines(_ body: String) throws -> [String] {
        let lines = body.components(separatedBy: "\r\n")
        let start = try #require(lines.firstIndex(where: { $0.hasPrefix("Content-Type: application/pdf") }))
        let end = try #require(lines[start...].firstIndex(of: ""))
        return Array(lines[start..<end])
    }

    /// The unfolded value of `name` in the given header lines (e.g. "Content-Disposition").
    private func headerValue(_ name: String, in lines: [String]) -> String? {
        guard let start = lines.firstIndex(where: { $0.hasPrefix("\(name): ") }) else { return nil }
        var value = String(lines[start].dropFirst(name.count + 2))
        var index = start + 1
        while index < lines.count, lines[index].hasPrefix(" ") {
            value += lines[index].dropFirst()
            index += 1
        }
        return value
    }

    /// Strict RFC 2231 decoding of `filename*=` / `filename*N*=`: indices must start at 0 and
    /// run without gaps or duplicates; only segment 0 carries `utf-8''`.
    private func decodeFilename(_ disposition: String) -> String? {
        var single: String?
        var numbered: [Int: String] = [:]
        for raw in disposition.split(separator: ";").dropFirst() {
            let part = raw.trimmingCharacters(in: .whitespaces)
            guard part.hasPrefix("filename*") else { return nil } // nothing else may be present
            let rest = part.dropFirst("filename*".count)
            if rest.hasPrefix("=") {
                guard single == nil, numbered.isEmpty else { return nil }
                single = String(rest.dropFirst())
            } else {
                guard let star = rest.firstIndex(of: "*"), let index = Int(rest[..<star]),
                      rest[rest.index(after: star)...].hasPrefix("="), numbered[index] == nil else { return nil }
                numbered[index] = String(rest[rest.index(star, offsetBy: 2)...])
            }
        }
        var joined: String
        if let single {
            joined = single
        } else {
            guard !numbered.isEmpty, numbered.keys.sorted() == Array(0..<numbered.count) else { return nil }
            guard numbered.keys.filter({ $0 > 0 }).allSatisfy({ !numbered[$0]!.hasPrefix("utf-8''") }) else { return nil }
            joined = (0..<numbered.count).map { numbered[$0]! }.joined()
        }
        guard joined.hasPrefix("utf-8''") else { return nil }
        joined.removeFirst("utf-8''".count)
        return joined.removingPercentEncoding
    }

    /// Decodes a Content-Type `name="=?utf-8?B?...?= =?utf-8?B?...?="` value.
    private func decodeName(_ contentType: String) -> String? {
        guard let start = contentType.range(of: "name=\""), contentType.hasSuffix("\"") else { return nil }
        let words = contentType[start.upperBound..<contentType.index(before: contentType.endIndex)]
        var bytes = Data()
        for word in words.split(separator: "=?utf-8?B?", omittingEmptySubsequences: true) {
            let b64 = word.replacingOccurrences(of: "?=", with: "").trimmingCharacters(in: .whitespaces)
            guard let data = Data(base64Encoded: b64) else { return nil }
            bytes += data
        }
        return String(data: bytes, encoding: .utf8)
    }

    private func check(_ name: String, expectedSanitized: String? = nil,
                       sourceLocation: SourceLocation = #_sourceLocation) throws {
        let lines = try attachmentHeaderLines(try composedBody(attachmentName: name))
        for line in lines {
            #expect(line.count <= 78, "\(line.count): \(line)", sourceLocation: sourceLocation)
            #expect(line.unicodeScalars.allSatisfy { $0.value < 0x80 }, "raw non-ASCII: \(line)", sourceLocation: sourceLocation)
        }
        let disposition = try #require(headerValue("Content-Disposition", in: lines), sourceLocation: sourceLocation)
        let contentType = try #require(headerValue("Content-Type", in: lines), sourceLocation: sourceLocation)
        let expected = expectedSanitized ?? name
        #expect(decodeFilename(disposition) == expected, "\(disposition)", sourceLocation: sourceLocation)
        #expect(decodeName(contentType) == expected, "\(contentType)", sourceLocation: sourceLocation)
        #expect(!disposition.contains("filename=\""), "no plain fallback", sourceLocation: sourceLocation)
    }

    @Test func asciiFilenameIsUnchanged() throws {
        let body = try composedBody(attachmentName: "report 2026.pdf")
        #expect(body.contains("Content-Type: application/pdf; name=\"report 2026.pdf\"\r\n"))
        #expect(body.contains("Content-Disposition: attachment; filename=\"report 2026.pdf\"\r\n"))
        #expect(!body.contains("filename*"))
    }

    @Test func accentedName() throws {
        let body = try composedBody(attachmentName: "Résumé.pdf")
        #expect(body.contains("Content-Disposition: attachment;\r\n filename*=utf-8''R%C3%A9sum%C3%A9.pdf\r\n"))
        #expect(body.contains("Content-Type: application/pdf;\r\n name=\"=?utf-8?B?UsOpc3Vtw6kucGRm?=\"\r\n"))
        try check("Résumé.pdf")
    }

    @Test func specialCharactersAreEncoded() throws {
        let name = "mon cv \"final\" 100% *v2* l'été;x=1.pdf"
        let disposition = try #require(headerValue("Content-Disposition", in: try attachmentHeaderLines(try composedBody(attachmentName: name))))
        // RFC 2231 requires %, *, ' and tspecials (here space, ", ;, =) to be encoded.
        for escape in ["%20", "%22", "%25", "%2A", "%27", "%3B", "%3D"] {
            #expect(disposition.contains(escape), "\(escape) missing in \(disposition)")
        }
        try check(name)
    }

    @Test func longNameUsesContinuations() throws {
        let name = String(repeating: "日本語のファイル名", count: 6) + ".pdf"
        let disposition = try #require(headerValue("Content-Disposition", in: try attachmentHeaderLines(try composedBody(attachmentName: name))))
        #expect(disposition.contains("filename*0*=utf-8''"))
        #expect(disposition.contains("filename*1*="))
        try check(name)
    }

    @Test func veryLongNameNeedsTenPlusContinuations() throws {
        let name = String(repeating: "é", count: 300) + ".pdf"
        let disposition = try #require(headerValue("Content-Disposition", in: try attachmentHeaderLines(try composedBody(attachmentName: name))))
        #expect(disposition.contains("filename*10*="))
        try check(name)
    }

    @Test func emojiAndCombiningCharacters() throws {
        try check("👨‍👩‍👧 photo e\u{301}.jpg")
    }

    @Test func bidiControlsAreStripped() throws {
        // U+202E would make "fdp.exe" display as "exe.pdf" in clients that decode the name.
        // Once stripped these names are plain ASCII, so they take the unchanged ASCII form.
        let spoof = try composedBody(attachmentName: "\u{202E}fdp.exe")
        #expect(spoof.contains("filename=\"fdp.exe\""))
        #expect(!spoof.contains("\u{202E}") && !spoof.contains("%E2%80%AE"))
        let isolates = try composedBody(attachmentName: "in\u{2067}voice\u{2069}\u{200F}.pdf")
        #expect(isolates.contains("filename=\"invoice.pdf\""))
        // Mixed with other non-ASCII text, the controls are still gone from the encoded form.
        try check("\u{202E}café.exe", expectedSanitized: "café.exe")
    }

    @Test func inlineResourceNonASCIIFilename() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.htmlBody = "<img src=\"cid:img1\">"
        message.inlineImages = [InlineResource(contentID: "img1", filename: "café.png", contentType: "image/png", data: Data([0, 1, 2]))]
        let body = String(decoding: try MIMEComposer(message).compose().body, as: UTF8.self)
        #expect(body.contains("Content-Disposition: inline;\r\n filename*=utf-8''caf%C3%A9.png\r\n"))
        #expect(body.contains("Content-Type: image/png;\r\n name=\"=?utf-8?B?Y2Fmw6kucG5n?=\"\r\n"))
    }
}

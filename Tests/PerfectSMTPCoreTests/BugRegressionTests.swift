//
//  BugRegressionTests.swift
//  PerfectSMTPCoreTests
//
//  First-class, named regressions for the two bugs this rewrite fixes
//  structurally (Documentation/swift6-nio-rewrite-plan.md §1, §4.7, §5):
//    Bug #1 — Bcc header leak.
//    Bug #2 — fake quoted-printable subject encoding.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct BugRegressionTests {

    // MARK: - Bug #1: Bcc header leak

    @Test func bug1_bccAddressLivesOnlyInEnvelopeRecipientsNeverInAnyHeader() throws {
        let bccAddress = "hidden@example.com"

        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Quarterly update"
        message.textBody = "hello"
        message.date = Date(timeIntervalSince1970: 1_700_000_000)
        message.messageID = "<fixed@example.com>"

        // EmailMessage has no `bcc` field at all — the caller-facing
        // `send(bcc:)` parameter (Phase 1) is what would place the Bcc
        // address here, directly in the envelope, never in the message.
        let envelope = try SMTPEnvelope(
            mailFrom: .address("ops@example.com"),
            recipients: ["user@dest.com", bccAddress]
        )

        #expect(envelope.recipients.contains(bccAddress))

        let composed = try MIMEComposer(message).compose()
        let serialized = String(decoding: composed.serialized(), as: UTF8.self)

        #expect(!serialized.contains(bccAddress))
        #expect(!composed.headers.contains { $0.name.caseInsensitiveCompare("Bcc") == .orderedSame })
    }

    @Test func bug1_extraHeadersCannotReintroduceBccByName() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [("Bcc", "hidden@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader("Bcc")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bug1_extraHeadersDenylistIsCaseInsensitive() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [("bCC", "hidden@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader("bCC")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test(arguments: ["To", "Cc", "From", "Return-Path", "Sender"])
    func bug1_otherRoutingCriticalHeadersAreAlsoDenied(name: String) {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [(name, "someone@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader(name)) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - Bug #2: fake quoted-printable subject encoding

    @Test func bug2_nonASCIISubjectIsGenuinelyEncodedNotFakeQP() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Rësúmé"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)

        // The old implementation's fallback branch emitted this exact
        // pattern: labeled quoted-printable but never actually encoded.
        // Assert it is not produced.
        #expect(subjectHeader != "=?utf-8?Q?Rësúmé?=")
        #expect(!subjectHeader.contains("é")) // no raw non-ASCII survives unescaped
        #expect(subjectHeader.hasPrefix("=?utf-8?B?"))
    }

    @Test func bug2_nonASCIISubjectRoundTripsCorrectly() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Rësúmé — 中文 — emoji \u{1F600}"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)

        #expect(decodeRFC2047(subjectHeader) == "Rësúmé — 中文 — emoji \u{1F600}")
    }

    @Test func bug2_asciiSubjectIsUnaffected() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Quarterly update"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)
        #expect(subjectHeader == "Quarterly update")
    }

    // MARK: - Bug #1 reopened: milestone review findings (architect/protocol/security passes)
    //
    // Three independent review passes against commit 6573e46 converged on
    // the same root cause: `sanitizeForHeader` was applied only to Subject
    // text and display-name phrases, never extended to the other
    // caller-controlled strings that also end up embedded raw into a
    // header line or the MAIL FROM command — reopening the Bcc-header-leak
    // bug through a different vector. Findings #1 and #2 below have a
    // working full-Bcc-injection repro, verified end-to-end through
    // `MIMEComposer`, not just at the `HeaderEncoder` unit level.

    @Test func finding1_addressCRLFInjectionCannotProduceALiveBccHeaderThroughCompose() {
        // Repro from the milestone review: `encodeAddress` returned
        // `address.address` completely raw. Verified end-to-end: this must
        // not be able to smuggle a Bcc header into a fully composed
        // message via `message.to`.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "victim@example.com>\r\nBcc: attacker@evil.com\r\nX-Injected: yes")]
        message.subject = "hi"
        message.textBody = "hello"

        #expect(throws: (any Error).self) {
            _ = try MIMEComposer(message).compose()
        }

        // Also confirm every address field (from, sender, replyTo, to, cc)
        // is covered, not just `to`.
        let malicious = EmailAddress(address: "victim@example.com>\r\nBcc: attacker@evil.com")

        var fromAttempt = EmailMessage(from: malicious)
        fromAttempt.to = [EmailAddress(address: "user@dest.com")]
        fromAttempt.textBody = "hello"
        #expect(throws: (any Error).self) { _ = try MIMEComposer(fromAttempt).compose() }

        var senderAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        senderAttempt.to = [EmailAddress(address: "user@dest.com")]
        senderAttempt.sender = malicious
        senderAttempt.textBody = "hello"
        #expect(throws: (any Error).self) { _ = try MIMEComposer(senderAttempt).compose() }

        var replyToAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        replyToAttempt.to = [EmailAddress(address: "user@dest.com")]
        replyToAttempt.replyTo = [malicious]
        replyToAttempt.textBody = "hello"
        #expect(throws: (any Error).self) { _ = try MIMEComposer(replyToAttempt).compose() }

        var toAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        toAttempt.to = [malicious]
        toAttempt.textBody = "hello"
        #expect(throws: (any Error).self) { _ = try MIMEComposer(toAttempt).compose() }

        var ccAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        ccAttempt.to = [EmailAddress(address: "user@dest.com")]
        ccAttempt.cc = [malicious]
        ccAttempt.textBody = "hello"
        #expect(throws: (any Error).self) { _ = try MIMEComposer(ccAttempt).compose() }
    }

    @Test func finding2_extraHeadersMangledNameCannotBypassDenylistToProduceALiveBccHeader() {
        // Repro from the milestone review: `extraHeaders = [("X-Foo\r\nBcc",
        // "attacker@evil.com")]` passed both the (name-based) denylist
        // check and the (CR/LF-clean) value check — a total bypass. Verify
        // end-to-end that composing this message throws, and — the
        // stronger assertion — that no serialized output containing a
        // live Bcc line is ever produced, under any caught-error path.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.extraHeaders = [("X-Foo\r\nBcc", "attacker@evil.com")]

        #expect(throws: (any Error).self) {
            _ = try MIMEComposer(message).compose()
        }

        // There is no serialized message to inspect (composition throws
        // before producing one) — which is itself the assertion: the old
        // bypass's defining characteristic was that composition
        // *succeeded* and silently included a Bcc line.
    }

    @Test func finding3_callerSuppliedMessageIDInReplyToAndReferencesRejectInjectionAttempts() {
        var messageIDAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        messageIDAttempt.textBody = "hi"
        messageIDAttempt.messageID = "<id@example.com>\r\nBcc: attacker@evil.com"
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("messageID")) {
            _ = try MIMEComposer(messageIDAttempt).compose()
        }

        var inReplyToAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        inReplyToAttempt.textBody = "hi"
        inReplyToAttempt.inReplyTo = "<id@example.com>\r\nBcc: attacker@evil.com"
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("inReplyTo")) {
            _ = try MIMEComposer(inReplyToAttempt).compose()
        }

        var referencesAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        referencesAttempt.textBody = "hi"
        referencesAttempt.references = ["<id@example.com>\r\nBcc: attacker@evil.com"]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("references")) {
            _ = try MIMEComposer(referencesAttempt).compose()
        }
    }

    @Test func finding4_attachmentAndInlineContentTypeInjectionAttemptsAreRejected() {
        var attachmentAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        attachmentAttempt.textBody = "hi"
        attachmentAttempt.attachments = [
            Attachment(
                filename: "a.txt",
                contentType: "text/plain\r\nX-Injected-CT: yes",
                data: Data("hi".utf8)
            ),
        ]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("attachment.contentType")) {
            _ = try MIMEComposer(attachmentAttempt).compose()
        }

        var inlineAttempt = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        inlineAttempt.textBody = "hi"
        inlineAttempt.inlineImages = [
            InlineResource(
                contentID: "img1",
                contentType: "image/png\r\nX-Injected-CT: yes",
                data: Data([0, 1, 2])
            ),
        ]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("inlineResource.contentType")) {
            _ = try MIMEComposer(inlineAttempt).compose()
        }
    }

    // `InlineResource.contentID` is embedded raw into the inline part's
    // `Content-ID` header, the same shape as `inlineResource.contentType`
    // above. Every CR/LF form must be rejected, with or without a filename.
    @Test(arguments: ["img1\r\nX-Injected-CID: yes", "img1\nX-Injected-CID: yes", "img1\rX-Injected-CID: yes", "img1\r\n\r\nbody"])
    func inlineResourceContentIDCRLFInjectionAttemptIsRejected(contentID: String) {
        for filename in [nil, "logo.png"] {
            var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
            message.htmlBody = "<p><img src=\"cid:img1\"></p>"
            message.inlineImages = [
                InlineResource(contentID: contentID, filename: filename, contentType: "image/png", data: Data([0, 1, 2])),
            ]
            #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("inlineResource.contentID")) {
                _ = try MIMEComposer(message).compose()
            }
        }
    }

    // MARK: - Bug #1 class, new vector: bodyContentTypeOverride CRLF injection
    //
    // `bodyContentTypeOverride` (added for the LassoPerfectSMTP
    // `-contentType`/`-transferEncoding` legacy dash-params) is a new
    // caller-controlled string that gets embedded raw into a MIME part's own
    // `Content-Type` header line -- the same injection shape as finding #4's
    // `attachment.contentType`/`inlineResource.contentType` above. Routed
    // through the identical `requireNoInjection` discipline, so a CRLF here
    // must throw, not silently strip, and must not be able to produce a live
    // extra header inside the body part.

    @Test func finding5_bodyContentTypeOverrideCRLFInjectionAttemptIsRejectedNotSilentlyStripped() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.bodyContentTypeOverride = "text/plain\r\nX-Injected-CT: yes"

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("bodyContentTypeOverride")) {
            _ = try MIMEComposer(message).compose()
        }

        // There is no serialized message to inspect (composition throws
        // before producing one) -- which is itself the assertion, matching
        // finding #2's precedent: the old-style bypass's defining
        // characteristic was that composition *succeeded* and silently
        // included the injected header line.
    }

    // MARK: - Bug #1 class, new vector: EmailMessage.charset CRLF injection
    //
    // LassoPerfectSMTP milestone review finding (security pass): unlike
    // `bodyContentTypeOverride` above, the *default* (non-override)
    // `Content-Type` construction path in `textLeaf` interpolated
    // `self.charset` (sourced from `EmailMessage.charset`, i.e. Lasso's
    // `-characterSet` dash-param) directly into the header string with no
    // `requireNoInjection` check at all -- a caller-supplied charset
    // containing CR/LF reached a live extra header, the same injection
    // shape as `bodyContentTypeOverride`'s already-covered vector, just on
    // the sibling code path that never got the same fix.

    @Test func finding6_charsetCRLFInjectionAttemptIsRejectedNotSilentlyEmbedded() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.charset = "utf-8\r\nBcc: attacker@evil.com"

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("charset")) {
            _ = try MIMEComposer(message).compose()
        }

        // As with finding #5: there is no serialized message to inspect --
        // composition throwing before producing one is itself the
        // assertion that no live extra header was ever embedded.
    }
}

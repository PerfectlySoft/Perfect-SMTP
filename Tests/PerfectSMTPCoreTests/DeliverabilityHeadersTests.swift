//
//  DeliverabilityHeadersTests.swift
//  PerfectSMTPCoreTests
//
//  Phase 5, Part 1: List-Unsubscribe/-Post (RFC 8058) and
//  Precedence/Auto-Submitted (RFC 3834-adjacent) header emission. See
//  Documentation/swift6-nio-rewrite-plan.md §7/§9's Phase 5 bullet.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct DeliverabilityHeadersTests {

    // MARK: - List-Unsubscribe / List-Unsubscribe-Post

    @Test func bothMailtoAndURLPresentProduceOneCommaSeparatedHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com", url: "https://example.com/unsub?id=123")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        // Folded to stay under 78 octets; compare the unfolded value.
        #expect(header.replacingOccurrences(of: "\r\n", with: "") == "<mailto:unsub@example.com>, <https://example.com/unsub?id=123>")
    }

    @Test func onlyMailtoPresentEmitsJustTheMailtoEntry() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<mailto:unsub@example.com>")
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func onlyURLPresentEmitsJustTheURLEntry() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://example.com/unsub?id=123")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<https://example.com/unsub?id=123>")
    }

    @Test func neitherMailtoNorURLPresentEmitsNoHeaderAtAll() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe()

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe" })
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func postOneClickTrueWithURLEmitsTheFixedLiteralHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(
            mailto: "unsub@example.com",
            url: "https://example.com/unsub?id=123",
            postOneClick: true
        )

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe-Post" }?.value)
        #expect(header == "List-Unsubscribe=One-Click")
    }

    @Test func postOneClickFalseNeverEmitsTheDashPostHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(
            mailto: "unsub@example.com",
            url: "https://example.com/unsub?id=123",
            postOneClick: false
        )

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func postOneClickTrueWithNoURLThrowsRatherThanSilentlyOmitting() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com", postOneClick: true)

        #expect(throws: MIMEComposer.ComposerError.postOneClickRequiresURL) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - FIX #1 (milestone review, protocol pass): RFC 8058 §3.1's
    // "MUST contain one HTTPS URI" -- checked unconditionally, not only
    // when postOneClick is true (this composer's always-HTTPS scope
    // decision; see ComposerError.listUnsubscribeURLMustBeHTTPS).

    @Test func httpURLWithPostOneClickTrueThrows() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "http://example.com/unsub?id=123", postOneClick: true)

        #expect(throws: MIMEComposer.ComposerError.listUnsubscribeURLMustBeHTTPS) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func httpURLWithPostOneClickFalseAlsoThrows() {
        // This composer's scope decision leans stricter than RFC 8058
        // §3.1's literal one-click-only "MUST": a plain, non-one-click
        // `List-Unsubscribe: <http://...>` is still a cleartext-downgrade
        // risk for whatever token the URL carries, so the HTTPS check
        // applies unconditionally to `url`, not gated on `postOneClick`.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "http://example.com/unsub?id=123", postOneClick: false)

        #expect(throws: MIMEComposer.ComposerError.listUnsubscribeURLMustBeHTTPS) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func unparsableURLStringAlsoThrowsTheSameHTTPSError() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "not a url at all")

        #expect(throws: MIMEComposer.ComposerError.listUnsubscribeURLMustBeHTTPS) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func genuineHTTPSURLComposesCorrectly() throws {
        // Confirms the already-covered happy path (bothMailtoAndURLPresentProduceOneCommaSeparatedHeader,
        // onlyURLPresentEmitsJustTheURLEntry, postOneClickTrueWithURLEmitsTheFixedLiteralHeader,
        // above) still succeeds now that the HTTPS check is in place -- not duplicating those,
        // just confirming this fix pass didn't regress the accept path.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://example.com/unsub?id=123", postOneClick: true)

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<https://example.com/unsub?id=123>")
    }

    // MARK: - CRLF-injection rejection (extends Phase 0's bug-regression style)

    @Test func mailtoCRLFInjectionAttemptIsRejected() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com\r\nBcc: attacker@evil.com")

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("listUnsubscribe.mailto")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func urlCRLFInjectionAttemptIsRejected() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://example.com/unsub\r\nBcc: attacker@evil.com")

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("listUnsubscribe.url")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func injectionAttemptNeverProducesASerializedLiveBccHeader() {
        // The stronger, end-to-end assertion (matching BugRegressionTests'
        // own style): composition throws before anything is serialized, so
        // there's no live message to inspect at all -- the old Bcc-leak
        // bug's defining characteristic was that composition *succeeded*.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com\r\nBcc: attacker@evil.com")

        #expect(throws: (any Error).self) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - FIX #3 (milestone review, security pass): List-Unsubscribe's
    // own list-delimiter characters (<, >, ,) must be rejected, distinct
    // from the CR/LF line-injection class above.

    @Test func urlContainingListDelimiterCharactersIsRejected() {
        // A url that stays within one header line (no CR/LF) but splices
        // an extra, attacker-chosen entry into List-Unsubscribe's own
        // comma-separated <uri> list -- e.g. a spoofed mailto: target.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://good.example.com/unsub>, <mailto:spoofed@attacker.example")

        #expect(throws: MIMEComposer.ComposerError.listUnsubscribeValueContainsDelimiterCharacter("listUnsubscribe.url")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func mailtoContainingListDelimiterCharactersIsRejected() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com>, <mailto:spoofed@attacker.example")

        #expect(throws: MIMEComposer.ComposerError.listUnsubscribeValueContainsDelimiterCharacter("listUnsubscribe.mailto")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - `mailto` already-`mailto:`-prefixed footgun (smaller fix,
    // robustness pass): the redundant prefix is stripped, not doubled.

    @Test func mailtoAlreadyPrefixedWithSchemeHasTheRedundantPrefixStripped() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "mailto:unsub@example.com")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<mailto:unsub@example.com>")
    }

    @Test func mailtoPrefixStrippingIsCaseInsensitive() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "MAILTO:unsub@example.com")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<mailto:unsub@example.com>")
    }

    // MARK: - Precedence / Auto-Submitted

    @Test(arguments: [Precedence.bulk, .list, .junk])
    func eachPrecedenceValueEmitsItsRawValue(precedence: Precedence) throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.precedence = precedence

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "Precedence" }?.value)
        #expect(header == precedence.rawValue)
    }

    @Test(arguments: [AutoSubmitted.autoGenerated, .autoReplied, .autoNotified])
    func eachAutoSubmittedValueEmitsItsRawValue(autoSubmitted: AutoSubmitted) throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.autoSubmitted = autoSubmitted

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "Auto-Submitted" }?.value)
        #expect(header == autoSubmitted.rawValue)
    }

    @Test func precedenceAndAutoSubmittedBothSetTogetherEmitBothHeaders() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.precedence = .bulk
        message.autoSubmitted = .autoGenerated

        let composed = try MIMEComposer(message).compose()
        #expect(composed.headers.first { $0.name == "Precedence" }?.value == "bulk")
        #expect(composed.headers.first { $0.name == "Auto-Submitted" }?.value == "auto-generated")
    }

    @Test func neitherPrecedenceNorAutoSubmittedSetEmitsNeitherHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "Precedence" })
        #expect(!composed.headers.contains { $0.name == "Auto-Submitted" })
    }
}

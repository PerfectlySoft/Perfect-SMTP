//
//  AddressSyntaxTests.swift
//  PerfectSMTPCoreTests
//
//  Release review: mailbox and hostname syntax, and the injection
//  payloads the reviewer sent through MAIL FROM / RCPT TO and the address
//  headers.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct AddressSyntaxTests {
    /// The reviewer's envelope payloads: each one reached the wire as an
    /// extra ESMTP parameter (or an extra mailbox) before this check.
    static let injectionPayloads = [
        "victim@example.test> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;spoof@evil.test",
        "a@example.test> SIZE=1 BODY=BINARYMIME SMTPUTF8 AUTH=<postmaster@example.test> RET=FULL ENVID=x",
        "a@example.test> ",
        "a\u{2028}@x.test",
        "\"quoted local\"@example.test",
        "<a@b>",
        "a@b\u{85}",
        "s@example.test>, <attacker@evil.test",
    ]

    @Test(arguments: [
        "user@example.com", "first.last+tag@sub.example.co.uk", "x@localhost", "a!#$%&'*+-/=?^_`{|}~@example.com",
        "user@[192.0.2.1]", "user@[IPv6:2001:db8::1]", "user@xn--bcher-kva.example", "UPPER@EXAMPLE.COM",
    ])
    func validMailboxesAreAccepted(address: String) {
        #expect(AddressSyntax.isMailbox(address))
    }

    @Test(arguments: injectionPayloads + [
        "", "@example.com", "user@", "user", "a@b@c", "user@exa mple.com", "us er@example.com", "user\u{A0}@example.com",
        "user@exämple.com", "üser@example.com", ".user@example.com", "user.@example.com", "us..er@example.com",
        "user@-example.com", "user@example-.com", "user@example..com", "user@example.com.", "user@[300.1.1.1]",
        "user@[1.2.3]", "user@[IPv6:zz::1]", "user@ex_ample.com", "user@\(String(repeating: "a", count: 64)).com".replacingOccurrences(of: "user", with: String(repeating: "u", count: 65)),
    ])
    func invalidMailboxesAreRejected(address: String) {
        #expect(!AddressSyntax.isMailbox(address))
    }

    @Test(arguments: injectionPayloads)
    func envelopeAddressesWithParametersOrMailboxListsAreRejected(address: String) {
        #expect(throws: (any Error).self) { _ = try ReversePath.address(address).mailFromCommand }
        #expect(throws: (any Error).self) { _ = try SMTPEnvelope(mailFrom: .null, recipients: [address]) }
    }

    @Test(arguments: injectionPayloads)
    func headerAddressesWithParametersOrMailboxListsAreRejected(address: String) {
        for build in [
            { (m: inout EmailMessage) in m.from = EmailAddress(displayName: "x", address: address) },
            { (m: inout EmailMessage) in m.to = [EmailAddress(address: address)] },
            { (m: inout EmailMessage) in m.cc = [EmailAddress(address: address)] },
            { (m: inout EmailMessage) in m.replyTo = [EmailAddress(address: address)] },
            { (m: inout EmailMessage) in m.sender = EmailAddress(address: address) },
        ] {
            var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
            message.to = [EmailAddress(address: "user@example.com")]
            message.textBody = "hi"
            build(&message)
            #expect(throws: (any Error).self) { _ = try MIMEComposer(message).compose() }
        }
    }

    /// The Message-ID domain is derived from From; with From validated it
    /// can no longer carry `>, <attacker@evil.test`.
    @Test func theSynthesizedMessageIDUsesAValidatedFromDomain() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@mail.example.com"))
        message.to = [EmailAddress(address: "user@example.com")]
        message.textBody = "hi"
        let composed = try MIMEComposer(message).compose()
        let id = try #require(composed.headers.first { $0.name == "Message-ID" }?.value)
        #expect(id.hasPrefix("<") && id.hasSuffix("@mail.example.com>"))
    }

    @Test(arguments: ["x.test>\r\nBcc: leak@evil.test\r\nX: <", "exa mple.com", "example.com>", "", "-bad.example"])
    func anInvalidMessageIDDomainIsRejected(domain: String) {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        #expect(throws: MIMEComposer.ComposerError.invalidMessageIDDomain(domain)) {
            _ = try MIMEComposer(message, messageIDDomain: domain).compose()
        }
    }

    @Test(arguments: ["b\"\r\nBcc: leak@evil.test", "", String(repeating: "a", count: 71), "ends-in-space ", "semi;colon", "quote\"", "ü"])
    func anInvalidBoundaryIsRejected(boundary: String) {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [Attachment(filename: "x.txt", contentType: "text/plain", data: Data("x".utf8))]
        #expect(throws: MIMEComposer.ComposerError.invalidBoundary(boundary)) {
            _ = try MIMEComposer(message, boundaryGenerator: { boundary }).compose()
        }
    }

    @Test(arguments: ["simple", "with space inside", "'()+_,-./:=?", String(repeating: "b", count: 70)])
    func aValidBoundaryIsAccepted(boundary: String) throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [Attachment(filename: "x.txt", contentType: "text/plain", data: Data("x".utf8))]
        let composed = try MIMEComposer(message, boundaryGenerator: { boundary }).compose()
        #expect(String(decoding: composed.body, as: UTF8.self).contains("--\(boundary)"))
    }

    @Test(arguments: [("exa mple.com", "s1"), ("example.com", "s 1"), ("example.com", "s1._domainkey;x"), ("example.com.", "s1"), ("", "s1"), ("example.com", "")])
    func anInvalidDKIMDomainOrSelectorIsRejected(domain: String, selector: String) throws {
        let key = SigningKey.ed25519(try .init(rawRepresentation: Data(repeating: 7, count: 32)))
        #expect(throws: (any Error).self) {
            _ = try DKIMSigner(domain: domain, selector: selector, signedHeaders: ["from"], keys: [key])
        }
    }
}

struct MessageIDSyntaxTests {
    private func base() -> EmailMessage {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        return message
    }

    @Test(arguments: ["<a@b> <c@d>", "a@b", "<>", "<a b@c>", "<a<b@c>"])
    func aCallerMessageIDMustBeOneMsgID(id: String) {
        var message = base(); message.messageID = id
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("messageID")) { _ = try MIMEComposer(message).compose() }
        message = base(); message.inReplyTo = id
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("inReplyTo")) { _ = try MIMEComposer(message).compose() }
        message = base(); message.references = ["<ok@example.com>", id]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("references")) { _ = try MIMEComposer(message).compose() }
    }

    @Test(arguments: ["a> <b", "a b", "<a>", ""])
    func aContentIDWithBracketsOrSpacesIsRejected(id: String) {
        var message = base()
        message.htmlBody = "<p>x</p>"
        message.inlineImages = [InlineResource(contentID: id, contentType: "image/png", data: Data([1]))]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("inlineResource.contentID")) { _ = try MIMEComposer(message).compose() }
    }
}

/// Release review nits: total length, and IPv6 literals.
struct AddressLiteralAndLengthTests {
    @Test func addressesAreCappedAt254Octets() {
        let domain = Array(repeating: String(repeating: "d", count: 63), count: 3).joined(separator: ".") + "." + String(repeating: "e", count: 57)
        let local62 = String(repeating: "l", count: 62)
        #expect(AddressSyntax.isMailbox(local62 + "@" + domain) == ((local62 + "@" + domain).utf8.count <= 254))
        #expect(!AddressSyntax.isMailbox(String(repeating: "l", count: 64) + "@" + domain))
        #expect(AddressSyntax.isMailbox("a@" + domain))
    }

    @Test(arguments: ["a@[IPv6:2001:db8::1]", "a@[ipv6:2001:db8::1]", "a@[IPV6:::1]", "a@[IPv6:1:2:3:4:5:6:7:8]",
                      "a@[IPv6:::ffff:192.0.2.1]", "a@[IPv6:fe80::]", "a@[IPv6:1::]"])
    func validIPv6LiteralsAreAccepted(address: String) {
        #expect(AddressSyntax.isMailbox(address))
    }

    @Test(arguments: ["a@[IPv6:::::]", "a@[IPv6:1::2::3]", "a@[IPv6:12345::1]", "a@[IPv6:1:2:3:4:5:6:7:8:9]",
                      "a@[IPv6:1:2:3:4:5:6:7]", "a@[IPv6::1]", "a@[IPv6:1:]", "a@[IPv6:]", "a@[IPv6:g::1]",
                      "a@[IPv6:::1.2.3]", "a@[IPv6:1.2.3.4::]", "a@[IPv6:1:2:3:4:5:6:7::8]"])
    func invalidIPv6LiteralsAreRejected(address: String) {
        #expect(!AddressSyntax.isMailbox(address))
    }
}

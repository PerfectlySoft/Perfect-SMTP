//
//  DKIMSignerTests.swift
//  PerfectSMTPCoreTests
//
//  DKIMSigner's own policy/behavior: the oversigning-of-absent-headers
//  correction (plan §4.6, RFC 6376 §5.4/§8.15), the injection scenario
//  that correction exists to defeat, dual RSA+Ed25519 signing, the
//  RSA-2048 minimum, and the DMARC-alignment lint. Deliberately separate
//  from DKIMRealVectorTests.swift, which exercises the RFC-vector-exact
//  hashing/signing algorithm independent of these policy decisions.
//

import Crypto
import Foundation
import Testing
@testable import PerfectSMTPCore
import _CryptoExtras

struct DKIMSignerTests {

    /// A real, freshly-generated 2048-bit RSA key (openssl genrsa 2048) --
    /// large enough to pass through `DKIMSigner`'s own RSA-2048 minimum
    /// unlike either RFC vector's illustrative 1024-bit key.
    fileprivate static let rsa2048PEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAwYYqnvIW69nFbGXs/1MlUxvZ6omQwRUQG4vXQvOsScGMPXXR
    ZiYhxblhM3IB+qJ1/x21yT0h0NaFSWMPE2uKxlG8+PPlYEdo7J0RdzX6zPP9AEz9
    eJGl0qEo2hIdHI/rXe5ROXFeG4c/cl4i3I1nDWlcS/g+A6dGtWbtCONlYnGXE5wS
    B6oVuJxOvKMlC0x1HuxQxeJ1K8gHfLg4LT4At4eNI8tuNMDPCLUbqmKvrmOO0SDO
    FD26mxiVoRHQxVX+Fm8xi4f2j2x1H2/rY+dpr8chepCCXGnqHA1GqYuq5zhgfx+o
    SGQgk1UJibN+ffvFxfXeVJIcrLaWYUe81XJg6wIDAQABAoIBAHKB6pIl+L4RGynq
    nXLuRbWJU0XdpBM7XU6PTg3FlPoHVe2/2ukwQud1qzf/i4A7xMnxUHEEhQ/G/xLP
    VEpPZcu27bP4zI5Ncp4eygjZnc7Lx7X32DsRIycgSMXP1f3igogPzWvJ0r9DJZ2M
    aeBKouFiqEQjXL5YqhQIFNUfiAvY1vvzz/xxV7bUQo1S7gmLKI6LGqbNiFTHo/sK
    RiRjO2G6/8G6R4pzOkE2rf1/gqckI/wVBCdaSeTym/tTw3/oFEgdA2qhwPisPhPv
    0BI30eJDtAhBuhUgXhVr5RZVYF84DcZPGQZq/l6mEvclDGJR6WisaAFqnq7fu0P0
    Pq2lB8ECgYEA4Gh+XDXngVVspP3LKg6p0udqW6C5IbjN0RUIHfhQhH6Lu3zrTFpX
    VZqd+aYciKD9HPxov+7YSMUjCFaDsJjqg75TRZuHbLVJkONhdiaOO0PU7588wNHm
    pwh/vneV5w6bqtiJCxOfH3FzH2CC5G5RQ2FBLBixZqoc5hQQLMKkqBsCgYEA3MSi
    BYNgSvL/VGN0EyVYuHdqBnSUFLRmdj0hvGR6JGaShoh7K8Oaz4a4v06jf9PUCdA5
    JJpBnZ+IFwQTyoMkbesleIQcFVRg0tTVU7PxEng2+Beg5qnNPuRuIYz7HvVn5xuu
    5kN2+wWEyz5oVhguJg7zg2p7RNWS+v7AsFEZV3ECgYEAofgJq/hkHZ9QiU19A+AN
    huHsjDHXLZW7R7uMXkVJqDfGFw60rilOe8TbXMMeOScpSXCNEmsLxIo1HOGEr0PP
    kEMgy07UUgwPCvpy79ooMnJlEIa4TNuzRMAHo6ugkGKkzIz5bPs+kG1MEEuSbdmJ
    4b4iUfeIo3cI4K9+dTAPtB0CgYBQeBvWhpyCtS/8QoP8tpAwLNaoo7WWFmuCjaXO
    VZFv0zN1dinvOc0j96c/lBpkbYHMUemCPffMzGl+ei38kvCkYCG4W+8glzDzqEBZ
    0iz83nSq2XH8ocf+NKUv9YNTNYA57Q1DQTQNK2XL72N4fjfUB38bV6S24mJAurrh
    ia4DAQKBgQDOmIn9iyXgGFMbldehPMU9RGKyJCMG47lBIaG9lg63SNLByJTdcn96
    6kNXD9cRbEEz86ebdtmC/4knKOSyN6ymPv7z5UPVvN8ezpNQiQ0ixS5AkTL3yYKv
    Qjb87l8lMbWyR5WKYbWVpsTPiEmw7iU4GptR5DXAbhzOBWY5VEo0WQ==
    -----END RSA PRIVATE KEY-----
    """

    /// RFC 8463 Appendix A's illustrative 1024-bit key -- used only to
    /// exercise the "too small" rejection path.
    fileprivate static let rsa1024PEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
    Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
    KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
    AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
    6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
    zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
    6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
    uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
    WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
    WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
    licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
    o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
    uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
    -----END RSA PRIVATE KEY-----
    """

    // MARK: - Oversigning policy (RFC 6376 §5.4/§8.15, plan §4.6)

    @Test func effectiveHeaderNamesOversignsAPresentMinimumHeaderToCountPlusOne() {
        let headers: [(name: String, value: String)] = [("From", "a@x.com"), ("Subject", "hi")]
        let result = DKIMSigner.effectiveHeaderNames(signedHeaders: [], actualHeaders: headers)
        #expect(result.filter { $0 == "from" }.count == 2)
        #expect(result.filter { $0 == "subject" }.count == 2)
    }

    @Test func effectiveHeaderNamesOversignsAnAbsentMinimumHeaderToExactlyOneEntry() {
        let headers: [(name: String, value: String)] = [("From", "a@x.com")]
        let result = DKIMSigner.effectiveHeaderNames(signedHeaders: [], actualHeaders: headers)
        // "Cc" never occurs in `headers` at all -- still gets one entry.
        #expect(result.filter { $0 == "cc" }.count == 1)
        // Likewise "Bcc" (this signer's deliberate addition to the plan's
        // literal minimum list -- see DKIMSigner.alwaysOversignedHeaders).
        #expect(result.filter { $0 == "bcc" }.count == 1)
        // FIX #2 (milestone review, Phase 5 fix pass): List-Unsubscribe/
        // -Post get the same "absent header still gets exactly one phantom
        // h= entry" treatment as Bcc -- see alwaysOversignedHeaders' doc
        // comment and RFC 8058 §4's DKIM-coverage requirement for these
        // two specifically.
        #expect(result.filter { $0 == "list-unsubscribe" }.count == 1)
        #expect(result.filter { $0 == "list-unsubscribe-post" }.count == 1)
    }

    @Test func effectiveHeaderNamesCoversTheFullPlanMinimumSetEvenWhenAllAbsent() {
        let result = DKIMSigner.effectiveHeaderNames(signedHeaders: [], actualHeaders: [])
        for name in ["from", "subject", "to", "cc", "date", "reply-to", "sender", "content-type", "mime-version"] {
            #expect(result.filter { $0 == name }.count == 1, "expected exactly one phantom entry for \(name)")
        }
    }

    @Test func effectiveHeaderNamesSignsANonMinimumCallerHeaderOnlyAtItsActualCount() {
        let headers: [(name: String, value: String)] = [("Message-ID", "<1@x.com>")]
        let result = DKIMSigner.effectiveHeaderNames(signedHeaders: ["message-id"], actualHeaders: headers)
        // Not in the always-oversigned minimum set -- signed once, not twice.
        #expect(result.filter { $0 == "message-id" }.count == 1)
    }

    @Test func effectiveHeaderNamesOmitsAGenuinelyAbsentNonMinimumCallerHeaderEntirely() {
        let result = DKIMSigner.effectiveHeaderNames(signedHeaders: ["in-reply-to"], actualHeaders: [])
        #expect(!result.contains("in-reply-to"))
    }

    // MARK: - The test that proves oversigning actually does its job

    @Test func oversignedButAbsentBccHeaderInvalidatesSignatureAfterLaterInjection() throws {
        let originalHeaders: [(name: String, value: String)] = [
            ("From", "Ops <ops@example.com>"),
            ("To", "User <user@example.com>"),
            ("Subject", "Test message"),
        ]
        let message = RFC5322Message(headers: originalHeaders, body: Array("hello\r\n".utf8))

        let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: Self.rsa2048PEM)
        let signer = try DKIMSigner(
            domain: "example.com",
            selector: "s1",
            signedHeaders: ["from", "to", "subject"],
            keys: [.rsa(privateKey)],
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        )

        let signed = try signer.sign(message)
        let dkimHeaderValue = try #require(signed.headers.first { $0.name == "DKIM-Signature" }?.value)

        // Bcc was absent from `originalHeaders` at signing time -- per the
        // corrected oversigning semantics, it still gets exactly one `h=`
        // entry (a "phantom": null contribution to the hash at signing
        // time, since there was no real Bcc header to sign yet).
        let hNamesAtSigningTime = DKIMSigner.effectiveHeaderNames(
            signedHeaders: ["from", "to", "subject"], actualHeaders: originalHeaders
        )
        #expect(hNamesAtSigningTime.filter { $0 == "bcc" }.count == 1)

        let (tagPrefix, signatureBase64) = try Self.splitOffSignature(dkimHeaderValue)
        let publicKey = privateKey.publicKey

        // Sanity check: verifying against the ORIGINAL, untampered headers
        // must succeed -- this proves the minimal verifier below is a real
        // check that can pass, not something that trivially always fails.
        #expect(Self.verifies(
            headers: originalHeaders, hNames: hNamesAtSigningTime,
            tagPrefix: tagPrefix, signatureBase64: signatureBase64, publicKey: publicKey
        ))

        // The attack this test exists to catch: an attacker injects a Bcc
        // header into the already-signed message. Naive oversigning (only
        // covering headers already present at signing time) would leave
        // this undetected, since Bcc was never in `h=` at all under that
        // (wrong) policy. Under the corrected policy, Bcc's phantom `h=`
        // entry now resolves to a REAL header at verification time,
        // changing the hash -- and the signature must no longer verify.
        let tamperedHeaders = originalHeaders + [("Bcc", "attacker@evil.example")]
        #expect(!Self.verifies(
            headers: tamperedHeaders, hNames: hNamesAtSigningTime,
            tagPrefix: tagPrefix, signatureBase64: signatureBase64, publicKey: publicKey
        ))
    }

    @Test func oversignedButAbsentListUnsubscribeHeaderInvalidatesSignatureAfterLaterInjection() throws {
        // Mirrors oversignedButAbsentBccHeaderInvalidatesSignatureAfterLaterInjection
        // above, extended to FIX #2's List-Unsubscribe addition (RFC 8058
        // §4's DKIM-coverage requirement for the one-click headers).
        let originalHeaders: [(name: String, value: String)] = [
            ("From", "Ops <ops@example.com>"),
            ("To", "User <user@example.com>"),
            ("Subject", "Test message"),
        ]
        let message = RFC5322Message(headers: originalHeaders, body: Array("hello\r\n".utf8))

        let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: Self.rsa2048PEM)
        let signer = try DKIMSigner(
            domain: "example.com",
            selector: "s1",
            signedHeaders: ["from", "to", "subject"],
            keys: [.rsa(privateKey)],
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        )

        let signed = try signer.sign(message)
        let dkimHeaderValue = try #require(signed.headers.first { $0.name == "DKIM-Signature" }?.value)

        let hNamesAtSigningTime = DKIMSigner.effectiveHeaderNames(
            signedHeaders: ["from", "to", "subject"], actualHeaders: originalHeaders
        )
        #expect(hNamesAtSigningTime.filter { $0 == "list-unsubscribe" }.count == 1)

        let (tagPrefix, signatureBase64) = try Self.splitOffSignature(dkimHeaderValue)
        let publicKey = privateKey.publicKey

        #expect(Self.verifies(
            headers: originalHeaders, hNames: hNamesAtSigningTime,
            tagPrefix: tagPrefix, signatureBase64: signatureBase64, publicKey: publicKey
        ))

        // The attack: an attacker (or a downstream relay stripping DKIM's
        // protection) injects a List-Unsubscribe header that was never
        // there at signing time -- e.g. to point Gmail/Yahoo's one-click
        // handler at an attacker-controlled endpoint. The phantom h= entry
        // now resolves to a REAL header at verification time, changing the
        // hash, so the signature must no longer verify.
        let tamperedHeaders = originalHeaders + [("List-Unsubscribe", "<https://attacker.example/unsub>")]
        #expect(!Self.verifies(
            headers: tamperedHeaders, hNames: hNamesAtSigningTime,
            tagPrefix: tagPrefix, signatureBase64: signatureBase64, publicKey: publicKey
        ))
    }

    /// Splits a produced `DKIM-Signature` tag-value string at its final
    /// `b=` tag, the way a minimal verifier would: everything up to and
    /// including `; b=` is the (already-canonicalizable) tag prefix with
    /// the signature value blanked out, matching RFC 6376 §3.7 step 2's
    /// "the value of the `b=` tag ... deleted (treated as the empty
    /// string)". Relies only on this signer's own tag ordering (`b=`
    /// always emitted last), which is an implementation detail of the
    /// *producer* here, not of the RFC itself -- a real verifier would
    /// instead do a proper tag-list parse; this shortcut is sufficient for
    /// a same-process round-trip test.
    private static func splitOffSignature(_ headerValue: String) throws -> (tagPrefix: String, signatureBase64: String) {
        // The header is folded; the signature is everything after the last
        // "b=", with its folding whitespace removed.
        let range = try #require(headerValue.range(of: "b=", options: .backwards))
        let tagPrefix = String(headerValue[..<range.upperBound])
        let signatureBase64 = String(headerValue[range.upperBound...]).filter { !$0.isWhitespace }
        return (tagPrefix, signatureBase64)
    }

    private static func verifies(
        headers: [(name: String, value: String)],
        hNames: [String],
        tagPrefix: String,
        signatureBase64: String,
        publicKey: _RSA.Signing.PublicKey
    ) -> Bool {
        let hashInput = DKIMSigningInput.headerHashInput(
            actualHeaders: headers, hNames: hNames, headerMode: .relaxed, dkimSignatureHeaderValue: tagPrefix
        )
        let digest = SHA256.hash(data: Data(hashInput))
        guard let signatureBytes = Data(base64Encoded: signatureBase64) else { return false }
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes)
        return publicKey.isValidSignature(signature, for: digest, padding: .insecurePKCS1v1_5)
    }

    // MARK: - Dual RSA + Ed25519 signing

    @Test func dualRSAAndEd25519SigningProducesTwoDistinctDKIMSignatureHeaders() throws {
        let rsaKey = try SigningKey.rsa(pem: Self.rsa2048PEM)
        let ed25519Key = try SigningKey.ed25519(rawRepresentation: Data(repeating: 7, count: 32))
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: ["from"], keys: [rsaKey, ed25519Key])
        let message = RFC5322Message(headers: [("From", "a@example.com")], body: Array("hi\r\n".utf8))

        let signed = try signer.sign(message)
        let dkimHeaders = signed.headers.filter { $0.name == "DKIM-Signature" }

        #expect(dkimHeaders.count == 2)
        #expect(dkimHeaders[0].value.contains("a=rsa-sha256"))
        #expect(dkimHeaders[1].value.contains("a=ed25519-sha256"))
        #expect(dkimHeaders[0].value != dkimHeaders[1].value)
        // Neither signing pass should have mutated the original headers or body.
        #expect(signed.headers.last?.name == "From")
        #expect(signed.body == Array("hi\r\n".utf8))
    }

    @Test func singleKeySigningProducesExactlyOneDKIMSignatureHeader() throws {
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: ["from"], keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)])
        let message = RFC5322Message(headers: [("From", "a@example.com")], body: Array("hi\r\n".utf8))
        let signed = try signer.sign(message)
        #expect(signed.headers.filter { $0.name == "DKIM-Signature" }.count == 1)
        // DKIM-Signature is prepended -- §3.5: "SHOULD be prepended to the message."
        #expect(signed.headers.first?.name == "DKIM-Signature")
    }

    // MARK: - RSA-2048 minimum enforcement

    @Test func constructingWithAnRSAKeySmallerThan2048BitsThrows() throws {
        let smallKey = try _RSA.Signing.PrivateKey(unsafePEMRepresentation: Self.rsa1024PEM)
        #expect(throws: DKIMSigner.ConfigurationError.rsaKeyTooSmall(bits: smallKey.keySizeInBits)) {
            _ = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: ["from"], keys: [.rsa(smallKey)])
        }
    }

    @Test func signingKeyRSAConvenienceRejectsSmallKeysAtParseTimeToo() {
        #expect(throws: (any Error).self) {
            _ = try SigningKey.rsa(pem: Self.rsa1024PEM)
        }
    }

    @Test func constructingWithNoKeysThrows() {
        #expect(throws: DKIMSigner.ConfigurationError.noSigningKeys) {
            _ = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: ["from"], keys: [])
        }
    }

    // MARK: - FIX #2 (milestone review, security pass): domain/selector
    // reach the signed `DKIM-Signature` header value unsanitized -- reject
    // CR/LF (and other C0 control characters) at construction time, the
    // same fail-loud discipline `HeaderEncoder.rejectHeaderInjection`
    // already applies to every other caller-controlled string embedded raw
    // into a header line.

    @Test func constructingWithACRLFLacedDomainThrows() throws {
        #expect(throws: (any Error).self) {
            _ = try DKIMSigner(
                domain: "example.com\r\nX-Injected: evil", selector: "s1", signedHeaders: ["from"],
                keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
            )
        }
    }

    @Test func constructingWithACRLFLacedSelectorThrows() throws {
        #expect(throws: (any Error).self) {
            _ = try DKIMSigner(
                domain: "example.com", selector: "s1\r\nX-Injected: evil", signedHeaders: ["from"],
                keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
            )
        }
    }

    // MARK: - FIX #3 (milestone review, security pass): redacted
    // description so an accidental `"\(signingKey)"`/`"\(dkimSigner)"`
    // interpolation can never leak key material.

    @Test func signingKeyDescriptionIsRedactedAndNamesTheAlgorithm() throws {
        let rsaKey = try SigningKey.rsa(pem: Self.rsa2048PEM)
        let ed25519Key = try SigningKey.ed25519(rawRepresentation: Data(repeating: 7, count: 32))
        #expect("\(rsaKey)" == "SigningKey(algorithm: rsa, <redacted>)")
        #expect("\(ed25519Key)" == "SigningKey(algorithm: ed25519, <redacted>)")
        #expect(String(reflecting: rsaKey) == "SigningKey(algorithm: rsa, <redacted>)")
    }

    /// Confirms `DKIMSigner`'s default, reflection-based description
    /// recurses into `SigningKey`'s own safe description for each element
    /// of `keys` -- i.e. that no separate `CustomStringConvertible`
    /// override is needed on `DKIMSigner` itself (see the doc comment on
    /// `DKIMSigner`'s stored properties).
    @Test func dkimSignerDescriptionRedactsItsKeysAndNeverContainsRawKeyMaterial() throws {
        let signer = try DKIMSigner(
            domain: "example.com", selector: "s1", signedHeaders: ["from"],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        let description = "\(signer)"
        #expect(description.contains("SigningKey(algorithm: rsa, <redacted>)"))
        // The PEM's base64 body must never appear in the description --
        // spot-check a distinctive substring from the middle of the key.
        #expect(!description.contains("wYYqnvIW69nFbGXs"))
    }

    // MARK: - DMARC-alignment lint (pure data, no logging in this target)

    @Test func isAlignedIsTrueForAnExactDomainMatch() throws {
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: [], keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)])
        #expect(signer.isAligned(withFromDomain: "ops@example.com"))
    }

    @Test func isAlignedIsTrueForASubdomainOfDUnderRelaxedAlignment() throws {
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: [], keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)])
        #expect(signer.isAligned(withFromDomain: "ops@mail.example.com"))
    }

    @Test func isAlignedIsFalseForAnUnrelatedDomain() throws {
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: [], keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)])
        #expect(!signer.isAligned(withFromDomain: "ops@evil.example"))
    }

    @Test func isAlignedIsFalseForAMalformedFromAddressWithNoAtSign() throws {
        let signer = try DKIMSigner(domain: "example.com", selector: "s1", signedHeaders: [], keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)])
        #expect(!signer.isAligned(withFromDomain: "not-an-address"))
    }

    // MARK: - FIX #1 (milestone review, DKIM/RFC-protocol expert pass):
    // isAligned must be a symmetric Organizational-Domain check, and must
    // reject a bare public suffix as `d=` per RFC 7489 §3.1.1's own named
    // example ("d=com" can never be "in alignment").

    /// Real bug #1 (false negative): a standard ESP/bulk-sender
    /// subdomain-signing config -- `d=bounces.example.com` signing
    /// `From: user@example.com` -- reduces to the same Organizational
    /// Domain (`example.com`) and RFC 7489 says it SHOULD align. The old
    /// one-directional check (`from` must be a descendant of `d`) reported
    /// this as misaligned; the fixed, symmetric check must not.
    @Test func isAlignedIsTrueForAnESPSubdomainSigningTheParentFromDomain() throws {
        let signer = try DKIMSigner(
            domain: "bounces.example.com", selector: "s1", signedHeaders: [],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        #expect(signer.isAligned(withFromDomain: "user@example.com"))
    }

    /// Real bug #2 (false positive): RFC 7489 §3.1.1 explicitly forbids
    /// treating a bare public suffix as an Organizational Domain -- "a DKIM
    /// signature bearing a value of 'd=com' would never allow an 'in
    /// alignment' result ... and therefore cannot be an Organizational
    /// Domain." `co.uk` is the RFC's own class of example (a common
    /// multi-label public suffix); `d=co.uk` must never align with any
    /// `*.co.uk` address, even though it would satisfy a naive suffix check.
    @Test func isAlignedIsFalseWhenDIsABarePublicSuffix() throws {
        let signer = try DKIMSigner(
            domain: "co.uk", selector: "s1", signedHeaders: [],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        #expect(!signer.isAligned(withFromDomain: "user@example.co.uk"))
    }

    /// Confirms the already-correct case is unaffected by the fix: `d=`
    /// one label below a public suffix (a genuine, non-bare Organizational
    /// Domain) still aligns with a deeper subdomain of itself.
    @Test func isAlignedIsTrueForARegistrableDomainBelowAPublicSuffixAligningWithItsOwnSubdomain() throws {
        let signer = try DKIMSigner(
            domain: "example.co.uk", selector: "s1", signedHeaders: [],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        #expect(signer.isAligned(withFromDomain: "user@anything.example.co.uk"))
    }
}

//
//  DKIMRealVectorTests.swift
//  PerfectSMTPCoreTests
//
//  The single most important test in Phase 2 (plan §4.6/§5): verifies the
//  RFC 6376 §3.7 signing algorithm (canonicalize -> select headers
//  bottom-up per §5.4.2 -> hash -> sign) against a REAL, PUBLISHED
//  test vector -- not an invented one, and not a self-consistency
//  round-trip against this package's own verification code (which would
//  prove nothing about RFC-correctness).
//
//  Vector source: RFC 8463 Appendix A (https://www.rfc-editor.org/rfc/rfc8463),
//  fetched directly via `curl https://www.rfc-editor.org/rfc/rfc8463.txt`.
//  This single message carries BOTH an RSA-SHA256 and an Ed25519-SHA256
//  DKIM-Signature over the identical body/headers/h=/bh=, which is why it
//  -- rather than RFC 6376 Appendix A alone -- is used as the primary
//  vector for both algorithms:
//
//  IMPORTANT, independently confirmed (not assumed) during implementation:
//  RFC 6376 Appendix A's OWN worked example (c=simple/simple) publishes a
//  `bh=` value (`2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=`) that does
//  NOT reproduce under RFC-conformant *simple* body canonicalization of
//  its stated message body -- it reproduces only under *relaxed* body
//  canonicalization (confirmed by hand computation: SHA-256 of the
//  simple-canonicalized body is `4bLNXImK9drULnmePzZNEBleUanJCX5PIsDIFoH4KTQ=`,
//  not the published value). This is a known inconsistency in RFC 6376's
//  own Appendix A, not a bug in this implementation -- RFC 8463 Appendix A
//  republishes the identical message under c=relaxed/relaxed and its
//  `bh=` IS internally consistent (confirmed by the same hand computation).
//  RFC 8463's vector is therefore used here as the byte-exact reference
//  instead of RFC 6376 Appendix A directly.
//
//  RSA-SHA256 (PKCS#1 v1.5) is deterministic, so this test reproduces the
//  published `b=` byte-for-byte -- independently cross-checked with
//  `openssl dgst -sha256 -sign`/`-verify` against this exact signing input
//  during implementation.
//
//  Ed25519-SHA256 is NOT byte-compared against the published `b=`: on
//  Apple platforms, swift-crypto's `Curve25519.Signing.PrivateKey.signature(for:)`
//  passes through to Apple CryptoKit, which intentionally randomizes its
//  EdDSA nonce as a side-channel defense (documented directly in
//  swift-crypto's own source, Sources/Crypto/Signatures/Ed25519.swift:
//  "the CryptoKit implementation of the algorithm employs randomization
//  to generate a different signature on every call, even for the same
//  data and key"). Two signatures of the identical input are therefore
//  both valid but not byte-identical (on Linux, BoringSSL's Ed25519 is
//  deterministic, but byte-comparing would still be Linux-only, so the same
//  approach is used everywhere) -- so this test instead verifies the
//  RFC's *published* Ed25519 signature against this implementation's
//  computed hash input using `isValidSignature`, which proves the
//  canonicalization/hash-construction is byte-exact (a forged or
//  differently-canonicalized hash input would fail verification) without
//  depending on nonce determinism this package does not control.
//

import Crypto
import Foundation
import Testing
@testable import PerfectSMTPCore
import _CryptoExtras

struct DKIMRealVectorTests {

    // MARK: - RFC 8463 Appendix A fixture (verbatim from the RFC text)

    private static let messageHeaders: [(name: String, value: String)] = [
        ("From", "Joe SixPack <joe@football.example.com>"),
        ("To", "Suzie Q <suzie@shopping.example.net>"),
        ("Subject", "Is dinner ready?"),
        ("Date", "Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"),
        ("Message-ID", "<20030712040037.46341.5F8J@football.example.com>"),
    ]

    /// RFC 8463 Appendix A.3's exact `h=` list, including the two
    /// repeated-but-nonexistent-a-second-time entries (from, subject,
    /// date each appear a second time, matching only one real occurrence
    /// each -- the second occurrence of each is a "phantom" per §5.4).
    private static let hNames = ["from", "to", "subject", "date", "message-id", "from", "subject", "date"]

    /// Fixed to the RFC's own `t=1528637909` so the DKIM-Signature tag
    /// text -- and therefore the hash input -- matches exactly.
    private static let hTagValue = "from : to : subject : date : message-id : from : subject : date"
    private static let bh = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="

    private static func tagValue(algorithm: String, selector: String) -> String {
        "v=1; a=\(algorithm); c=relaxed/relaxed; d=football.example.com; i=@football.example.com; " +
            "q=dns/txt; s=\(selector); t=1528637909; h=\(hTagValue); bh=\(bh); b="
    }

    // MARK: - RSA-SHA256 (byte-exact -- PKCS#1 v1.5 is deterministic)

    private static let rsaPrivateKeyPEM = """
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

    private static let publishedRSASignature =
        "F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3" +
        "DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz" +
        "dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8="

    @Test func rsaSHA256ReproducesRFC8463sPublishedSignatureByteForByte() throws {
        // This key is the RFC's own 1024-bit illustrative key -- below the
        // RFC 6376/plan-mandated RSA-2048 minimum this signer enforces at
        // construction, so it's used here via swift-crypto's *unsafe*
        // (sub-2048-permitting) initializer, bypassing `SigningKey.rsa(pem:)`
        // and `DKIMSigner` entirely. This test exercises the RFC 6376 §3.7
        // signing algorithm (`DKIMSigningInput.headerHashInput` +
        // `.insecurePKCS1v1_5` signing) directly, independent of
        // `DKIMSigner`'s own 2048-bit floor -- that floor is exercised
        // separately in `DKIMSignerTests`, against a real 2048-bit key.
        let privateKey = try _RSA.Signing.PrivateKey(unsafePEMRepresentation: Self.rsaPrivateKeyPEM)

        let dkimTagValue = Self.tagValue(algorithm: "rsa-sha256", selector: "test")
        let hashInput = DKIMSigningInput.headerHashInput(
            actualHeaders: Self.messageHeaders,
            hNames: Self.hNames,
            headerMode: .relaxed,
            dkimSignatureHeaderValue: dkimTagValue
        )

        let digest = SHA256.hash(data: Data(hashInput))
        let signature = try privateKey.signature(for: digest, padding: .insecurePKCS1v1_5)
        let computedB = signature.rawRepresentation.base64EncodedString()

        #expect(computedB == Self.publishedRSASignature)
    }

    @Test func rsaSHA256sPublishedSignatureVerifiesAgainstThisImplementationsHashInput() throws {
        // The converse direction, using only the published PUBLIC key
        // (never touching the private key) -- proves this is a genuine
        // "does our hash input match what the real signer hashed" check,
        // not merely "we can reproduce a signature with a key we also
        // control."
        let publicKeyDER = try #require(Data(
            base64Encoded: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" +
                "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" +
                "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" +
                "Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
        ))
        let publicKey = try _RSA.Signing.PublicKey(unsafeDERRepresentation: publicKeyDER)

        let dkimTagValue = Self.tagValue(algorithm: "rsa-sha256", selector: "test")
        let hashInput = DKIMSigningInput.headerHashInput(
            actualHeaders: Self.messageHeaders,
            hNames: Self.hNames,
            headerMode: .relaxed,
            dkimSignatureHeaderValue: dkimTagValue
        )
        let digest = SHA256.hash(data: Data(hashInput))
        let publishedSignatureBytes = try #require(Data(base64Encoded: Self.publishedRSASignature))
        let signature = _RSA.Signing.RSASignature(rawRepresentation: publishedSignatureBytes)

        #expect(publicKey.isValidSignature(signature, for: digest, padding: .insecurePKCS1v1_5))
    }

    // MARK: - Ed25519-SHA256 (verified, not byte-compared -- see file header)

    private static let ed25519SeedBase64 = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
    private static let ed25519PublicKeyBase64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    private static let publishedEd25519Signature =
        "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus" +
        "Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="

    @Test func ed25519SHA256sPublishedSignatureVerifiesAgainstThisImplementationsHashInput() throws {
        let publicKeyRaw = try #require(Data(base64Encoded: Self.ed25519PublicKeyBase64))
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw)

        let dkimTagValue = Self.tagValue(algorithm: "ed25519-sha256", selector: "brisbane")
        let hashInput = DKIMSigningInput.headerHashInput(
            actualHeaders: Self.messageHeaders,
            hNames: Self.hNames,
            headerMode: .relaxed,
            dkimSignatureHeaderValue: dkimTagValue
        )
        // RFC 8463 §3: the DKIM data-hash (SHA-256 over the RFC 6376 §3.7
        // signing input) is itself what gets PureEdDSA-signed -- the
        // 32-byte digest is the "message" Ed25519 signs, not the raw
        // signing input.
        let digest = Data(SHA256.hash(data: Data(hashInput)))
        let publishedSignatureBytes = try #require(Data(base64Encoded: Self.publishedEd25519Signature))

        #expect(publicKey.isValidSignature(publishedSignatureBytes, for: digest))
    }

    @Test func ed25519SHA256RoundTripsWithThisImplementationsOwnSigningKey() throws {
        // Sanity companion to the verification-only test above: this
        // package's own `SigningKey.ed25519` signing (via `sign(_:)`)
        // produces a signature that verifies against the RFC's published
        // public key for the RFC's real message -- confirming the
        // implementation can both consume (verify) and produce
        // (sign-then-verify) against the same real-world key material,
        // even though the produced signature bytes themselves are
        // intentionally non-deterministic (see file header).
        let seed = try #require(Data(base64Encoded: Self.ed25519SeedBase64))
        let signingKey = try SigningKey.ed25519(rawRepresentation: seed)

        let dkimTagValue = Self.tagValue(algorithm: "ed25519-sha256", selector: "brisbane")
        let hashInput = DKIMSigningInput.headerHashInput(
            actualHeaders: Self.messageHeaders,
            hNames: Self.hNames,
            headerMode: .relaxed,
            dkimSignatureHeaderValue: dkimTagValue
        )
        let producedB = try signingKey.sign(hashInput)
        let producedSignatureBytes = try #require(Data(base64Encoded: producedB))

        let publicKeyRaw = try #require(Data(base64Encoded: Self.ed25519PublicKeyBase64))
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw)
        let digest = Data(SHA256.hash(data: Data(hashInput)))

        #expect(publicKey.isValidSignature(producedSignatureBytes, for: digest))
    }

    @Test func ed25519SigningDeterminismMatchesThePlatformBackend() throws {
        // Documents, as an executable fact rather than only a code
        // comment, exactly why the two tests above verify rather than
        // byte-compare. On Apple platforms swift-crypto passes through to
        // CryptoKit, whose randomized nonce makes two signatures of the
        // identical input, from the identical key, differ (both still
        // valid). Elsewhere swift-crypto uses BoringSSL's RFC 8032 Ed25519,
        // which is deterministic, so the same two signatures are identical.
        // Verification-only tests are correct on both.
        let seed = try #require(Data(base64Encoded: Self.ed25519SeedBase64))
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let message = Data("fixed DKIM data-hash stand-in".utf8)

        let first = try privateKey.signature(for: message)
        let second = try privateKey.signature(for: message)

        #if canImport(CryptoKit)
        #expect(first != second)
        #else
        #expect(first == second)
        #endif
        #expect(privateKey.publicKey.isValidSignature(first, for: message))
        #expect(privateKey.publicKey.isValidSignature(second, for: message))
    }

    // MARK: - bh= itself, independent of either signing algorithm

    @Test func bodyHashMatchesRFC8463sPublishedBhAcrossBothSignatures() {
        // The message body is "Hi.\r\n\r\nWe lost the game.  Are you hungry
        // yet?\r\n\r\nJoe.\r\n" (RFC 8463 Appendix A.3) -- both signatures
        // in the vector share the same published `bh=`.
        let body = Array("Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n".utf8)
        let canon = DKIMCanonicalization.canonicalizeBody(body, mode: .relaxed)
        let hash = Data(SHA256.hash(data: Data(canon))).base64EncodedString()
        #expect(hash == Self.bh)
    }
}

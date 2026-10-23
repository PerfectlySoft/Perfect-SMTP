//
//  CertificateDNSNamesTests.swift
//  PerfectSMTPTests
//
//  The subjectAltName dNSName parser behind `requireCertificateDNSName`:
//  the test CA's real certificates, hand-built DER, and malformed input.
//

import NIOSSL
import Testing
@testable import PerfectSMTP

struct CertificateDNSNamesTests {
    private static func der(_ pem: String) throws -> [UInt8] {
        try NIOSSLCertificate(bytes: Array(pem.utf8), format: .pem).toDERBytes()
    }

    // Minimal DER builders (definite lengths, up to 65535 bytes).
    private static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        let n = body.count
        let length: [UInt8] = n < 0x80 ? [UInt8(n)] : n < 0x100 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 0xFF)]
        return [tag] + length + body
    }
    private static func seq(_ items: [UInt8]...) -> [UInt8] { tlv(0x30, items.flatMap { $0 }) }
    private static let sanOID: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x11]
    private static let keyUsageOID: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0F]

    /// Certificate { TBS { [0] version, serial, [3] { Extensions } } } with
    /// just enough structure for the parser.
    private static func certificate(extensions: [[UInt8]]) -> [UInt8] {
        let tbs = seq(tlv(0xA0, tlv(0x02, [2])), tlv(0x02, [1]), tlv(0xA3, seq(extensions.flatMap { $0 })))
        return seq(tbs, seq(tlv(0x06, [0x2A])), tlv(0x03, [0]))
    }
    private static func sanExtension(_ generalNames: [[UInt8]]) -> [UInt8] {
        seq(sanOID, tlv(0x04, seq(generalNames.flatMap { $0 })))
    }
    private static func dnsName(_ name: String) -> [UInt8] { tlv(0x82, Array(name.utf8)) }
    private static func ipAddress(_ bytes: [UInt8]) -> [UInt8] { tlv(0x87, bytes) }

    @Test func theTestCertificatesParse() throws {
        #expect(try CertificateDNSNames.dnsNames(fromDER: Self.der(TestCertificates.namedCertificatePEM)) == ["mx.victim.test"])
        #expect(try CertificateDNSNames.dnsNames(fromDER: Self.der(TestCertificates.dnsOnlyCertificatePEM)) == ["mx.victim.test"])
        #expect(try CertificateDNSNames.dnsNames(fromDER: Self.der(TestCertificates.ipOnlyCertificatePEM)).isEmpty)
        #expect(try CertificateDNSNames.dnsNames(fromDER: Self.der(TestCertificates.caPEM)).isEmpty)
    }

    @Test func handBuiltNamesAndMatching() throws {
        let der = Self.certificate(extensions: [
            Self.seq(Self.keyUsageOID, Self.tlv(0x01, [0xFF]), Self.tlv(0x04, Self.tlv(0x03, [0x05, 0xA0]))),
            Self.sanExtension([Self.ipAddress([127, 0, 0, 1]), Self.dnsName("*.Victim.Test"), Self.dnsName("bücher.test"), Self.dnsName("mail.example.test")]),
        ])
        #expect(try CertificateDNSNames.dnsNames(fromDER: der) == ["*.Victim.Test", "mail.example.test"])
        #expect(throws: Never.self) { try CertificateDNSNames.requireMatch(certificateDER: der, host: "mx.victim.test") }
        #expect(throws: Never.self) { try CertificateDNSNames.requireMatch(certificateDER: der, host: "MAIL.example.TEST") }
        // A wildcard covers exactly one label.
        #expect(throws: CertificateNameError.noDNSName(host: "a.mx.victim.test")) {
            try CertificateDNSNames.requireMatch(certificateDER: der, host: "a.mx.victim.test")
        }
        #expect(throws: CertificateNameError.noDNSName(host: "victim.test")) {
            try CertificateDNSNames.requireMatch(certificateDER: der, host: "victim.test")
        }
        // An IP SAN never satisfies a name.
        let ipOnly = Self.certificate(extensions: [Self.sanExtension([Self.ipAddress([127, 0, 0, 1])])])
        #expect(throws: CertificateNameError.noDNSName(host: "127.0.0.1")) {
            try CertificateDNSNames.requireMatch(certificateDER: ipOnly, host: "127.0.0.1")
        }
    }

    @Test func noExtensionsMeansNoNames() throws {
        let tbs = Self.seq(Self.tlv(0x02, [1]))
        #expect(try CertificateDNSNames.dnsNames(fromDER: Self.seq(tbs)).isEmpty)
    }

    @Test(arguments: [
        [], [0x30], [0x30, 0x05, 0x30], [0x02, 0x01, 0x01], [0x30, 0x03, 0x02, 0x01, 0x01],
        [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], Array(repeating: 0x30, count: 64),
    ] as [[UInt8]])
    func malformedDERIsRejected(bytes: [UInt8]) {
        #expect(throws: CertificateNameError.malformedCertificate) { _ = try CertificateDNSNames.dnsNames(fromDER: bytes) }
    }

    @Test func malformedExtensionsAreRejected() {
        let cases: [[UInt8]] = [
            // extnValue isn't DER.
            Self.certificate(extensions: [Self.seq(Self.sanOID, Self.tlv(0x04, [0xFF, 0xFF, 0x00]))]),
            // extnValue isn't an OCTET STRING.
            Self.certificate(extensions: [Self.seq(Self.sanOID, Self.tlv(0x0C, Self.seq()))]),
            // GeneralNames isn't a SEQUENCE.
            Self.certificate(extensions: [Self.seq(Self.sanOID, Self.tlv(0x04, Self.tlv(0x31, [])))]),
            // An extension with only an OID.
            Self.certificate(extensions: [Self.seq(Self.sanOID)]),
            // A constructed dNSName.
            Self.certificate(extensions: [Self.sanExtension([Self.tlv(0xA2, Self.dnsName("x"))])]),
            // [3] holding two things.
            Self.seq(Self.seq(Self.tlv(0xA3, Self.seq() + Self.seq())), Self.seq(), Self.tlv(0x03, [0])),
        ]
        for der in cases {
            #expect(throws: CertificateNameError.malformedCertificate) { _ = try CertificateDNSNames.dnsNames(fromDER: der) }
        }
    }

    /// Random mutations of a real certificate never crash; they either
    /// parse or throw `.malformedCertificate`.
    @Test func mutatedCertificatesNeverCrash() throws {
        let base = try Self.der(TestCertificates.namedCertificatePEM)
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<2000 {
            var bytes = base
            for _ in 0..<Int.random(in: 1...6, using: &generator) {
                let i = Int.random(in: 0..<bytes.count, using: &generator)
                switch Int.random(in: 0..<3, using: &generator) {
                case 0: bytes[i] = UInt8.random(in: 0...255, using: &generator)
                case 1: bytes.remove(at: i)
                default: bytes.insert(UInt8.random(in: 0...255, using: &generator), at: i)
                }
            }
            do { _ = try CertificateDNSNames.dnsNames(fromDER: bytes) } catch {
                #expect(error as? CertificateNameError == .malformedCertificate)
            }
        }
    }
}

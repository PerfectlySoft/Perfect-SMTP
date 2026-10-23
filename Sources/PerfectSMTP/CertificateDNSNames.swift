//
//  CertificateDNSNames.swift
//  PerfectSMTP
//
//  The DNS-name check behind `requireCertificateDNSName`. NIOSSL's own
//  hostname check also accepts an iPAddress subjectAltName equal to the
//  dialed address, so a certificate issued for an IP can stand in for a
//  host name. Where a name is required (relay TLS, MTA-STS delivery, the
//  MTA-STS policy fetch), the peer certificate must carry a dNSName that
//  matches the host. This runs after the handshake, on the certificate
//  NIOSSL has already verified, through public API only: NIOSSL's
//  `peerCertificate` and `toDERBytes()`, then a small subjectAltName parser
//  on swift-asn1 (already in the graph through swift-crypto).
//

import NIOCore
import NIOSSL
import SwiftASN1

/// The certificate verified as a chain but didn't name the host as
/// required.
public enum CertificateNameError: Error, Sendable, Equatable {
    /// No DNS subjectAltName matches `host`.
    case noDNSName(host: String)
    /// The handshake completed without a peer certificate to check.
    case noPeerCertificate
    /// The certificate's DER couldn't be parsed far enough to read its
    /// subjectAltName extension.
    case malformedCertificate
}

enum CertificateDNSNames {
    /// The subjectAltName extension, RFC 5280 §4.2.1.6.
    private static let subjectAltNameOID: [UInt] = [2, 5, 29, 17]

    /// Every dNSName in the certificate's subjectAltName extension(s), as
    /// written. Throws `CertificateNameError.malformedCertificate` if the
    /// DER doesn't have the X.509 shape up to and including the
    /// extensions. A certificate without a subjectAltName returns `[]`.
    static func dnsNames(fromDER der: [UInt8]) throws -> [String] {
        do {
            let certificate = try children(of: DER.parse(der), universal: 0x10)
            guard let tbsNode = certificate.first else { throw CertificateNameError.malformedCertificate }
            let tbs = try children(of: tbsNode, universal: 0x10)
            // extensions [3] EXPLICIT Extensions (RFC 5280 §4.1).
            guard let wrapper = tbs.first(where: { $0.identifier.tagClass == .contextSpecific && $0.identifier.tagNumber == 3 }) else {
                return []
            }
            let wrapped = try children(of: wrapper)
            guard wrapped.count == 1 else { throw CertificateNameError.malformedCertificate }
            var names: [String] = []
            for extensionNode in try children(of: wrapped[0], universal: 0x10) {
                // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
                let parts = try children(of: extensionNode, universal: 0x10)
                guard (2...3).contains(parts.count) else { throw CertificateNameError.malformedCertificate }
                let oid = try ASN1ObjectIdentifier(derEncoded: parts[0])
                guard oid.oidComponents == subjectAltNameOID else { continue }
                let value = try primitive(parts[parts.count - 1], universal: 0x04)
                // GeneralNames ::= SEQUENCE OF GeneralName; dNSName [2] IMPLICIT IA5String.
                for general in try children(of: DER.parse(value), universal: 0x10)
                where general.identifier.tagClass == .contextSpecific && general.identifier.tagNumber == 2 {
                    guard case .primitive(let bytes) = general.content else { throw CertificateNameError.malformedCertificate }
                    // IA5String: ASCII only. Anything else can't name a host.
                    guard !bytes.isEmpty, bytes.allSatisfy({ (0x21...0x7E).contains($0) }) else { continue }
                    names.append(String(decoding: bytes, as: UTF8.self))
                }
            }
            return names
        } catch let error as CertificateNameError {
            throw error
        } catch {
            throw CertificateNameError.malformedCertificate
        }
    }

    /// Throws `CertificateNameError.noDNSName` unless one of the
    /// certificate's dNSNames matches `host`: equal ignoring ASCII case, or
    /// a `*.` wildcard covering exactly one leading label (the same rule as
    /// MTA-STS `mx:` patterns, `MXPatternMatcher`).
    static func requireMatch(certificateDER der: [UInt8], host: String) throws {
        let names = try dnsNames(fromDER: der)
        guard names.contains(where: { MXPatternMatcher.matches(pattern: $0, host: host) }) else {
            throw CertificateNameError.noDNSName(host: host)
        }
    }

    /// Runs `requireMatch` on the certificate the TLS handler in
    /// `pipeline` received. Call once the handshake has completed.
    static func requireMatch(in pipeline: ChannelPipeline.SynchronousOperations, host: String) throws {
        let handler = try pipeline.handler(type: NIOSSLClientHandler.self)
        guard let certificate = handler.peerCertificate else { throw CertificateNameError.noPeerCertificate }
        try requireMatch(certificateDER: certificate.toDERBytes(), host: host)
    }

    private static func children(of node: ASN1Node, universal tag: UInt? = nil) throws -> [ASN1Node] {
        if let tag {
            guard node.identifier.tagClass == .universal, node.identifier.tagNumber == tag else {
                throw CertificateNameError.malformedCertificate
            }
        }
        guard case .constructed(let collection) = node.content else { throw CertificateNameError.malformedCertificate }
        return Array(collection)
    }

    private static func primitive(_ node: ASN1Node, universal tag: UInt) throws -> [UInt8] {
        guard node.identifier.tagClass == .universal, node.identifier.tagNumber == tag,
              case .primitive(let bytes) = node.content
        else { throw CertificateNameError.malformedCertificate }
        return Array(bytes)
    }
}

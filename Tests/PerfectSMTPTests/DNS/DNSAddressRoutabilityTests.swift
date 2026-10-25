//
//  DNSAddressRoutabilityTests.swift
//  PerfectSMTPTests
//
//  FIX #2 (plan §9 Phase 3 milestone security review): `DNSAddress
//  .isRoutable` is the SSRF-class filter `DirectMXTransport.makeDialer`
//  applies to every resolved address before dialing it. Pure value-type
//  tests -- no network, no NIO channel, no resolver involved -- covering
//  every range the review named "at minimum," plus the IPv4-mapped-IPv6
//  bypass this implementation additionally closes.
//

import NIOCore
import Testing
@testable import PerfectSMTP

struct DNSAddressRoutabilityTests {
    // MARK: - IPv4: RFC 1918 private ranges

    @Test func rfc1918TenSlashEightIsNotRoutable() {
        #expect(!DNSAddress.v4([10, 0, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([10, 255, 255, 255]).isRoutable)
    }

    @Test func rfc1918OneSevenTwoSlashTwelveIsNotRoutable() {
        #expect(!DNSAddress.v4([172, 16, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([172, 31, 255, 255]).isRoutable)
        // Outside the /12 range (172.16.0.0-172.31.255.255) -- must remain routable.
        #expect(DNSAddress.v4([172, 15, 255, 255]).isRoutable)
        #expect(DNSAddress.v4([172, 32, 0, 0]).isRoutable)
    }

    @Test func rfc1918OneNineTwoOneSixEightIsNotRoutable() {
        #expect(!DNSAddress.v4([192, 168, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([192, 168, 255, 255]).isRoutable)
    }

    // MARK: - IPv4: loopback

    @Test func ipv4LoopbackIsNotRoutable() {
        #expect(!DNSAddress.v4([127, 0, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([127, 255, 255, 255]).isRoutable)
    }

    // MARK: - IPv4: link-local, including the cloud-metadata address

    @Test func ipv4LinkLocalIsNotRoutable() {
        #expect(!DNSAddress.v4([169, 254, 0, 1]).isRoutable)
    }

    @Test func cloudMetadataAddressIsNotRoutable() {
        #expect(!DNSAddress.v4([169, 254, 169, 254]).isRoutable)
    }

    // MARK: - IPv4: RFC 6598 carrier-grade NAT

    @Test func rfc6598CGNATIsNotRoutable() {
        #expect(!DNSAddress.v4([100, 64, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([100, 127, 255, 255]).isRoutable)
        // Outside the /10 range -- must remain routable.
        #expect(DNSAddress.v4([100, 63, 255, 255]).isRoutable)
        #expect(DNSAddress.v4([100, 128, 0, 0]).isRoutable)
    }

    // MARK: - IPv4: ordinary public addresses remain routable

    @Test func ordinaryPublicIPv4AddressesRemainRoutable() {
        #expect(DNSAddress.v4([8, 8, 8, 8]).isRoutable)
        #expect(DNSAddress.v4([93, 184, 216, 34]).isRoutable)
        #expect(DNSAddress.v4([1, 1, 1, 1]).isRoutable)
    }

    // MARK: - IPv6: loopback, unspecified, link-local, unique-local

    @Test func ipv6LoopbackIsNotRoutable() {
        let loopback: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        #expect(!DNSAddress.v6(loopback).isRoutable)
    }

    @Test func ipv6UnspecifiedIsNotRoutable() {
        let unspecified = [UInt8](repeating: 0, count: 16)
        #expect(!DNSAddress.v6(unspecified).isRoutable)
    }

    @Test func ipv6LinkLocalIsNotRoutable() {
        // fe80::1
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[0] = 0xFE
        bytes[1] = 0x80
        bytes[15] = 1
        #expect(!DNSAddress.v6(bytes).isRoutable)
    }

    @Test func ipv6UniqueLocalIsNotRoutable() {
        // fc00::1 and fd00::1 -- both within fc00::/7.
        var fcBytes = [UInt8](repeating: 0, count: 16)
        fcBytes[0] = 0xFC
        fcBytes[15] = 1
        #expect(!DNSAddress.v6(fcBytes).isRoutable)

        var fdBytes = [UInt8](repeating: 0, count: 16)
        fdBytes[0] = 0xFD
        fdBytes[15] = 1
        #expect(!DNSAddress.v6(fdBytes).isRoutable)
    }

    @Test func ordinaryPublicIPv6AddressRemainsRoutable() {
        // 2606:4700:10::6814:179a (a real, public Cloudflare address).
        let bytes: [UInt8] = [0x26, 0x06, 0x47, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x68, 0x14, 0x17, 0x9A]
        #expect(DNSAddress.v6(bytes).isRoutable)
    }

    // MARK: - IPv6: IPv4-mapped bypass (`::ffff:a.b.c.d`)

    @Test func ipv4MappedIPv6EncodingOfALoopbackAddressIsNotRoutable() {
        // ::ffff:127.0.0.1 -- the classic SSRF-filter bypass: an AAAA
        // record carrying a filtered IPv4 address inside an IPv6 wrapper.
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[10] = 0xFF
        bytes[11] = 0xFF
        bytes[12] = 127
        bytes[13] = 0
        bytes[14] = 0
        bytes[15] = 1
        #expect(!DNSAddress.v6(bytes).isRoutable)
    }

    @Test func ipv4MappedIPv6EncodingOfAPublicAddressRemainsRoutable() {
        // ::ffff:8.8.8.8
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[10] = 0xFF
        bytes[11] = 0xFF
        bytes[12] = 8
        bytes[13] = 8
        bytes[14] = 8
        bytes[15] = 8
        #expect(DNSAddress.v6(bytes).isRoutable)
    }
}

/// Table tests over the IANA IPv4 and IPv6 special-purpose registries.
struct DNSAddressSpecialPurposeRangeTests {
    private struct NotIPv6: Error {}

    private static func v6(_ text: String) throws -> DNSAddress {
        // Parse via NIOCore so the table can be written in normal notation.
        var bytes = [UInt8](repeating: 0, count: 16)
        let address = try SocketAddress(ipAddress: text, port: 0)
        guard case .v6(let v6) = address else { throw NotIPv6() }
        withUnsafeBytes(of: v6.address.sin6_addr) { raw in for i in 0..<16 { bytes[i] = raw[i] } }
        return .v6(bytes)
    }

    private static func v4(_ text: String) -> DNSAddress { .v4(text.split(separator: ".").map { UInt8($0)! }) }

    @Test(arguments: [
        "0.0.0.0", "0.1.2.3", "10.1.1.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
        "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
        "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
    ])
    func ipv4SpecialPurposeAddressesAreNotRoutable(address: String) {
        #expect(!Self.v4(address).isRoutable)
    }

    @Test(arguments: ["1.1.1.1", "8.8.8.8", "93.184.216.34", "192.0.1.1", "192.88.98.1", "198.20.0.1", "223.255.255.255", "100.128.0.1"])
    func ipv4GlobalUnicastAddressesAreRoutable(address: String) {
        #expect(Self.v4(address).isRoutable)
    }

    @Test(arguments: [
        "::", "::1", "::127.0.0.1", "::8.8.8.8", "::ffff:127.0.0.1", "::ffff:0.0.0.0", "::ffff:10.0.0.1",
        "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::808:808", "100::1", "fc00::1", "fd12:3456::1",
        "fe80::1", "fec0::1", "ff02::1", "ff0e::1", "2001::1", "2001:2::1", "2001:10::1", "2001:db8::1",
        "2002:7f00:1::", "2002:a00:1::1", "2002:0:0::1", "3fff::1", "4000::1", "e000::1",
    ])
    func ipv6NonGlobalAddressesAreNotRoutable(address: String) throws {
        #expect(try !Self.v6(address).isRoutable)
    }

    @Test(arguments: [
        "2606:4700:4700::1111", "2a00:1450:4001:81a::200e", "2001:4860:4860::8888", "2001:200::1",
        "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
    ])
    func ipv6GlobalUnicastAddressesAreRoutable(address: String) throws {
        #expect(try Self.v6(address).isRoutable)
    }
}

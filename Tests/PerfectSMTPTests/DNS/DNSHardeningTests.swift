//
//  DNSHardeningTests.swift
//  PerfectSMTPTests
//
//  Release review: label bytes and name length on decode, question and
//  owner-name matching, ignoring malformed or mismatched datagrams, and
//  resolveAddresses reporting a timeout instead of "no records". Uses the
//  local FakeDNSServer on 127.0.0.1.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DNSHardeningTests {
    private static func aRecord(owner: String, address: [UInt8]) -> [UInt8] {
        var bytes = TestDNSMessageBuilder.name(owner)
        bytes += [0, 1, 0, 1, 0, 0, 0, 60, 0, 4]
        bytes += address
        return bytes
    }

    // MARK: - Decoding

    /// The reviewer's packet: an MX whose exchange label is `mx\0`. It used
    /// to decode to "mx\u{0}.victim.test", which matches `*.victim.test`.
    /// The label is now escaped, and the exchange is refused as a host name.
    @Test func aLabelWithANULByteIsEscapedAndRefusedAsAnExchange() throws {
        var packet: [UInt8] = [0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 15, 0, 1, 0, 0, 0, 60]
        let rdata: [UInt8] = [0, 10, 3, 0x6D, 0x78, 0x00, 6] + Array("victim".utf8) + [4] + Array("test".utf8) + [0]
        packet += [0, UInt8(rdata.count)] + rdata
        let message = try DNSMessage.decode(packet)
        guard case .mx(_, let exchange) = message.answers.first?.rdata else {
            Issue.record("expected an MX record")
            return
        }
        #expect(exchange == "mx\\000.victim.test")
        // It still looks like one label under *.victim.test, but it is not a
        // host name, so it is never dialed or used for SNI.
        #expect(!AddressSyntax.isHostname(exchange))
        #expect(throws: DNSResolver.ResolveError.malformedResponse) { _ = try DNSResolver.processMXAnswers(message.answers) }
    }

    @Test(arguments: [([0x61, 0x2E, 0x62], "a\\046b"), ([0x61, 0x20], "a\\032"), ([0x61, 0x7F], "a\\127"), ([0xC3, 0xA9], "\\195\\169"), ([0x0A], "\\010"), ([0x5C], "\\092")] as [([UInt8], String)])
    func unusualLabelBytesAreEscapedNotTrusted(label: [UInt8], expected: String) throws {
        var packet = TestDNSMessageBuilder.header(id: 1, isResponse: true, ancount: 0)
        packet += [UInt8(label.count)] + label + [0, 0, 1, 0, 1]
        let message = try DNSMessage.decode(packet)
        #expect(message.questions.first?.name == expected)
        #expect(!AddressSyntax.isHostname(expected))
    }

    /// An odd name in another record no longer rejects the whole response.
    @Test func anOddNameElsewhereDoesNotRejectAValidAnswer() throws {
        let odd: [UInt8] = [3, 0x6D, 0x00, 0x78, 0] // one label: "m", NUL, "x"
        let bytes = TestDNSMessageBuilder.response(id: 7, qname: "mx.victim.test", qtype: 1, records: [
            odd + [0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1],
            Self.aRecord(owner: "mx.victim.test", address: [93, 184, 216, 34]),
        ])
        let message = try DNSMessage.decode(bytes)
        let (addresses, _) = DNSResolver.extractAddresses(from: message, type: .a, name: "mx.victim.test")
        #expect(addresses == [.v4([93, 184, 216, 34])])
    }

    @Test func aNameLongerThan255OctetsIsRejectedOnDecodeAndEncode() {
        // Five 63-octet labels: 5 * 64 + 1 = 321 octets on the wire.
        let long = (0..<5).map { _ in String(repeating: "a", count: 63) }.joined(separator: ".")
        var packet = TestDNSMessageBuilder.header(id: 1, isResponse: true, ancount: 0)
        packet += TestDNSMessageBuilder.question(name: long, type: 1)
        #expect(throws: DNSWireError.nameTooLong) { _ = try DNSMessage.decode(packet) }
        #expect(throws: DNSWireError.nameTooLong) { _ = try DNSMessage.encodeQuery(id: 1, name: long, type: .a) }
        // Exactly 255: three 63s, one 61 -> 3 * 64 + 62 + 1 = 255.
        let max = ((0..<3).map { _ in String(repeating: "b", count: 63) } + [String(repeating: "c", count: 61)]).joined(separator: ".")
        #expect(throws: Never.self) { _ = try DNSMessage.encodeQuery(id: 1, name: max, type: .a) }
    }

    // MARK: - Matching

    @Test func aResponseForADifferentQuestionIsNotValid() throws {
        let response = try DNSMessage.decode(TestDNSMessageBuilder.response(id: 7, qname: "evil.test", qtype: 1, records: []))
        #expect(!DNSTransport.isValidResponse(response, expectedID: 7, name: "victim.test", type: .a))
        #expect(!DNSTransport.isValidResponse(response, expectedID: 7, name: "evil.test", type: .aaaa))
        #expect(DNSTransport.isValidResponse(response, expectedID: 7, name: "EVIL.test.", type: .a))
    }

    @Test func addressesOwnedBySomeOtherNameAreIgnored() throws {
        let bytes = TestDNSMessageBuilder.response(id: 7, qname: "mx.victim.test", qtype: 1, records: [
            Self.aRecord(owner: "other.test", address: [127, 0, 0, 1]),
            Self.aRecord(owner: "mx.victim.test", address: [93, 184, 216, 34]),
        ])
        let message = try DNSMessage.decode(bytes)
        let (addresses, cname) = DNSResolver.extractAddresses(from: message, type: .a, name: "mx.victim.test")
        #expect(addresses == [.v4([93, 184, 216, 34])])
        #expect(cname == nil)
    }

    @Test func aCNAMEChainInsideOneAnswerIsFollowedToItsOwner() throws {
        let bytes = TestDNSMessageBuilder.response(id: 7, qname: "www.victim.test", qtype: 1, records: [
            TestDNSMessageBuilder.cnameRecord(owner: "www.victim.test", target: "edge.victim.test"),
            Self.aRecord(owner: "unrelated.test", address: [10, 0, 0, 1]),
            Self.aRecord(owner: "edge.victim.test", address: [93, 184, 216, 34]),
        ])
        let (addresses, _) = DNSResolver.extractAddresses(from: try DNSMessage.decode(bytes), type: .a, name: "www.victim.test")
        #expect(addresses == [.v4([93, 184, 216, 34])])
    }

    // MARK: - Over the wire

    @Test(.timeLimit(.minutes(1)))
    func malformedAndMismatchedDatagramsAreIgnoredUntilTheRealReply() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let real = TestDNSMessageBuilder.response(id: 0, qname: "mx.victim.test", qtype: 1, records: [
            Self.aRecord(owner: "mx.victim.test", address: [93, 184, 216, 34]),
        ])
        let wrongQuestion = TestDNSMessageBuilder.response(id: 0, qname: "evil.test", qtype: 1, records: [
            Self.aRecord(owner: "evil.test", address: [127, 0, 0, 1]),
        ])
        let garbage: [UInt8] = [0, 0, 0x81, 0x80, 0, 1, 0, 1, 0xFF, 0xFF]
        let server = try await FakeDNSServer.start(group: group, udpResponses: [
            FakeDNSServer.scriptKey(name: "mx.victim.test", type: .a): .init(real, decoys: [garbage, wrongQuestion]),
        ])
        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(5))
        let addresses = try await resolver.resolveAddressesOfType(.a, name: "mx.victim.test")
        await server.shutdown()
        try await group.shutdownGracefully()
        #expect(addresses == [.v4([93, 184, 216, 34])])
    }

    /// A nameserver that never answers used to surface as `.noRecordsFound`
    /// (both families' timeouts swallowed by `try?`), which DirectMX treats
    /// as "use the implicit MX" or a permanent failure. It is a timeout.
    @Test(.timeLimit(.minutes(1)))
    func resolveAddressesReportsATimeoutRatherThanNoRecords() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await FakeDNSServer.start(group: group, udpResponses: [:]) // drops every query
        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .milliseconds(100))
        await #expect(throws: DNSResolver.ResolveError.timeout) {
            _ = try await resolver.resolveAddresses(hostname: "mx.victim.test")
        }
        await server.shutdown()
        try await group.shutdownGracefully()
    }
}

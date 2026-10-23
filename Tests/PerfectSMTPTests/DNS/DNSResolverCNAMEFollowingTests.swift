//
//  DNSResolverCNAMEFollowingTests.swift
//  PerfectSMTPTests
//
//  End-to-end (against `FakeDNSServer`, not `EmbeddedChannel`) tests of
//  `DNSResolver.resolveAddressesOfType(_:name:)`'s bounded CNAME-chain
//  following (plan §9 Phase 3, point 3): a real multi-hop chain resolving
//  successfully, a genuine two-name cycle being rejected promptly rather
//  than hanging, and a long-but-non-repeating chain exceeding
//  `DNSResolver.maximumCNAMEHops` being rejected the same way. This can't
//  be tested as a pure function the way `DNSResolverMXOrderingTests` and
//  `DNSAddressExtractionTests` are -- chain-following genuinely spans
//  multiple independent queries, which needs a live (if local and fast)
//  query loop to exercise.
//

import Foundation
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DNSResolverCNAMEFollowingTests {

    @Test func followsAMultiHopCNAMEChainToATerminalARecord() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        var responses: [String: FakeDNSUDPHandler.ScriptedResponse] = [:]
        responses[FakeDNSServer.scriptKey(name: "start.chain.test", type: .a)] =
            .init(cnameResponse(owner: "start.chain.test", target: "middle.chain.test"))
        responses[FakeDNSServer.scriptKey(name: "middle.chain.test", type: .a)] =
            .init(cnameResponse(owner: "middle.chain.test", target: "end.chain.test"))
        responses[FakeDNSServer.scriptKey(name: "end.chain.test", type: .a)] =
            .init(aResponse(owner: "end.chain.test", address: [10, 1, 1, 1]))

        let server = try await FakeDNSServer.start(group: group, udpResponses: responses)
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        let addresses = try await resolver.resolveAddressesOfType(.a, name: "start.chain.test")
        #expect(addresses.count == 1)
        #expect(addresses[0].description == "10.1.1.1")
    }

    @Test func aTwoNameCNAMECycleIsRejectedPromptlyRatherThanHanging() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        var responses: [String: FakeDNSUDPHandler.ScriptedResponse] = [:]
        responses[FakeDNSServer.scriptKey(name: "a.loop.test", type: .a)] =
            .init(cnameResponse(owner: "a.loop.test", target: "b.loop.test"))
        responses[FakeDNSServer.scriptKey(name: "b.loop.test", type: .a)] =
            .init(cnameResponse(owner: "b.loop.test", target: "a.loop.test"))

        let server = try await FakeDNSServer.start(group: group, udpResponses: responses)
        defer { Task { await server.shutdown() } }

        // A long query timeout, so any path that waits for one stands out
        // clearly from three local round trips even under TSan or
        // emulation (where those alone took over a second).
        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(10))

        let start = DispatchTime.now()
        await #expect(throws: DNSResolver.ResolveError.cnameLoop) {
            _ = try await resolver.resolveAddressesOfType(.a, name: "a.loop.test")
        }
        let elapsedSeconds = TimeInterval(DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000_000
        // The cycle is caught the moment "a.loop.test" is revisited (the
        // third hop: a -> b -> a) -- three fast local queries, not
        // anywhere close to `queryTimeout`'s 10 s budget. A regression that
        // turned this into a hang (or fell through to exhausting the
        // 8-hop bound via repeated timeouts) would take at least that.
        #expect(elapsedSeconds < 8, "cycle detection took \(elapsedSeconds)s -- expected it to be caught almost immediately via the visited-name guard, not by exhausting retries/hops")
    }

    @Test func aChainLongerThanTheHopBoundIsRejectedWithoutACycle() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        // A strictly-increasing, never-repeating chain of names, one
        // longer than `DNSResolver.maximumCNAMEHops` (8) -- h0 -> h1 -> ...
        // -> h8, where h8 is never actually queried because the bound is
        // hit first. No name repeats, so this specifically exercises the
        // hop-count cap, not the visited-set cycle guard.
        var responses: [String: FakeDNSUDPHandler.ScriptedResponse] = [:]
        for hop in 0..<8 {
            let owner = "h\(hop).chain.test"
            let target = "h\(hop + 1).chain.test"
            responses[FakeDNSServer.scriptKey(name: owner, type: .a)] = .init(cnameResponse(owner: owner, target: target))
        }

        let server = try await FakeDNSServer.start(group: group, udpResponses: responses)
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        await #expect(throws: DNSResolver.ResolveError.cnameLoop) {
            _ = try await resolver.resolveAddressesOfType(.a, name: "h0.chain.test")
        }
    }

    // MARK: - Fixture helpers

    private func cnameResponse(owner: String, target: String) -> [UInt8] {
        TestDNSMessageBuilder.response(
            id: 0, qname: owner, qtype: 1, records: [TestDNSMessageBuilder.cnameRecord(owner: owner, target: target)]
        )
    }

    private func aResponse(owner: String, address: [UInt8]) -> [UInt8] {
        var record = TestDNSMessageBuilder.name(owner)
        record.append(0x00); record.append(0x01) // TYPE=A
        record.append(0x00); record.append(0x01) // CLASS=IN
        record.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL=60
        record.append(0x00); record.append(0x04) // RDLENGTH=4
        record.append(contentsOf: address)
        return TestDNSMessageBuilder.response(id: 0, qname: owner, qtype: 1, records: [record])
    }
}

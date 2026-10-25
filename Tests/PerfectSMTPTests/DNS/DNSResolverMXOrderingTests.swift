//
//  DNSResolverMXOrderingTests.swift
//  PerfectSMTPTests
//
//  `DNSResolver.processMXAnswers(_:)` is the pure RFC 5321 §5.1
//  preference-ordering + equal-preference-randomization logic, plus the
//  RFC 7505 null-MX distinction -- tested here directly against hand-built
//  `DNSResourceRecord` values (and, for the null-MX case, the real captured
//  wire fixture decoded first) with no network involved.
//

import Testing
@testable import PerfectSMTP

struct DNSResolverMXOrderingTests {

    private static func mxRecord(preference: UInt16, exchange: String) -> DNSResourceRecord {
        DNSResourceRecord(name: "example.org", type: 15, recordClass: 1, ttl: 300, rdata: .mx(preference: preference, exchange: exchange))
    }

    // MARK: - Ordering

    @Test func sortsAscendingByPreferenceAcrossGroups() throws {
        let records = [
            Self.mxRecord(preference: 20, exchange: "c.example.org"),
            Self.mxRecord(preference: 10, exchange: "a.example.org"),
            Self.mxRecord(preference: 30, exchange: "d.example.org"),
        ]
        let resolved = try DNSResolver.processMXAnswers(records)
        #expect(resolved.map(\.preference) == [10, 20, 30])
        #expect(resolved.map(\.exchange) == ["a.example.org", "c.example.org", "d.example.org"])
    }

    @Test func equalPreferenceGroupContainsExactlyTheRightHostsRegardlessOfOrder() throws {
        let records = [
            Self.mxRecord(preference: 10, exchange: "a.example.org"),
            Self.mxRecord(preference: 10, exchange: "b.example.org"),
            Self.mxRecord(preference: 10, exchange: "c.example.org"),
            Self.mxRecord(preference: 20, exchange: "d.example.org"),
        ]
        let resolved = try DNSResolver.processMXAnswers(records)
        #expect(resolved.count == 4)
        // The first three positions are the preference-10 group -- its
        // *set* of hosts must be exactly {a,b,c} regardless of the shuffled
        // internal order; the fourth position is the lone preference-20
        // host.
        let firstGroup = Set(resolved.prefix(3).map(\.exchange))
        #expect(firstGroup == ["a.example.org", "b.example.org", "c.example.org"])
        #expect(resolved[3].exchange == "d.example.org")
        #expect(resolved.prefix(3).allSatisfy { $0.preference == 10 })
    }

    /// Statistical regression guard (plan's explicit ask): confirms equal-
    /// preference records are genuinely re-shuffled per call, not just
    /// "correct membership but always emitted in the same relative order"
    /// -- which a stable sort (or a `shuffled()` regression that got
    /// silently dropped) would still pass the membership-only test above.
    /// With 5 equally-preferred hosts (120 possible orderings) and 200
    /// independent calls, the odds of observing only a single distinct
    /// ordering by chance are astronomically small if shuffling is
    /// actually happening -- this is not a flake-prone marginal statistic.
    @Test func equalPreferenceGroupIsReshuffledAcrossCalls() throws {
        let records = (0..<5).map { Self.mxRecord(preference: 10, exchange: "\($0).example.org") }
        var observedOrderings = Set<[String]>()
        for _ in 0..<200 {
            let resolved = try DNSResolver.processMXAnswers(records)
            observedOrderings.insert(resolved.map(\.exchange))
        }
        #expect(observedOrderings.count > 1, "expected multiple distinct shuffles across 200 calls, got \(observedOrderings.count) -- looks like the sort is stable rather than shuffling equal-preference groups")
    }

    // MARK: - Null-MX (RFC 7505) vs. empty answers

    @Test func nullMXRecordThrowsDistinctlyFromNoRecordsFound() {
        let nullRecord = [Self.mxRecord(preference: 0, exchange: "")]
        #expect(throws: DNSResolver.ResolveError.nullMX) {
            _ = try DNSResolver.processMXAnswers(nullRecord)
        }

        #expect(throws: DNSResolver.ResolveError.noRecordsFound) {
            _ = try DNSResolver.processMXAnswers([])
        }
    }

    @Test func nullMXRecordDecodedFromARealCapturedResponseThrowsNullMX() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.exampleComNullMXResponse)
        #expect(throws: DNSResolver.ResolveError.nullMX) {
            _ = try DNSResolver.processMXAnswers(message.answers)
        }
    }

    @Test func nullMXAlsoRecognizesTheTextualRootFormExchange() {
        let nullRecord = [Self.mxRecord(preference: 0, exchange: ".")]
        #expect(throws: DNSResolver.ResolveError.nullMX) {
            _ = try DNSResolver.processMXAnswers(nullRecord)
        }
    }

    /// A single preference-0 record pointing at a *real* host is a normal,
    /// common configuration (the domain's only/most-preferred MX) -- it
    /// must never be misclassified as RFC 7505's null-MX, which requires
    /// the exchange to be the root specifically.
    @Test func singlePreferenceZeroRecordWithARealExchangeIsNotNullMX() throws {
        let records = [Self.mxRecord(preference: 0, exchange: "mail.example.org")]
        let resolved = try DNSResolver.processMXAnswers(records)
        #expect(resolved == [DNSResolver.MXRecord(preference: 0, exchange: "mail.example.org")])
    }

    /// RFC 7505 §3 forbids publishing a null MX alongside other MX
    /// records, and §4 says not to deliver to a domain with a null MX. The
    /// RFC doesn't address the mixed (misconfigured) case, so the release
    /// review settled it conservatively: any null MX in the RRset means
    /// "this domain accepts no mail" rather than falling through to the
    /// other records.
    @Test func aNullMXAlongsideAnotherRecordIsStillNullMX() {
        let records = [
            Self.mxRecord(preference: 0, exchange: ""),
            Self.mxRecord(preference: 10, exchange: "mail.example.org"),
        ]
        #expect(throws: DNSResolver.ResolveError.nullMX) { _ = try DNSResolver.processMXAnswers(records) }
    }

    /// A root exchange at a non-zero preference isn't a null MX, but it
    /// can't be dialed either: it's dropped, and the real host kept.
    @Test func aRootExchangeAtANonZeroPreferenceIsDropped() throws {
        let records = [
            Self.mxRecord(preference: 5, exchange: ""),
            Self.mxRecord(preference: 10, exchange: "mail.example.org"),
        ]
        #expect(try DNSResolver.processMXAnswers(records) == [DNSResolver.MXRecord(preference: 10, exchange: "mail.example.org")])
    }

    @Test(arguments: ["mx\u{0}.victim.test", "mx .victim.test", "-mx.victim.test", "mx_.victim.test"])
    func aNonHostnameExchangeIsDroppedAndAnAllInvalidSetIsMalformed(exchange: String) throws {
        #expect(throws: DNSResolver.ResolveError.malformedResponse) {
            _ = try DNSResolver.processMXAnswers([Self.mxRecord(preference: 10, exchange: exchange)])
        }
        let mixed = [Self.mxRecord(preference: 10, exchange: exchange), Self.mxRecord(preference: 20, exchange: "mx2.victim.test")]
        #expect(try DNSResolver.processMXAnswers(mixed) == [DNSResolver.MXRecord(preference: 20, exchange: "mx2.victim.test")])
    }
}

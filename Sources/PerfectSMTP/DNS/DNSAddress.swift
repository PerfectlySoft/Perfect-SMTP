//
//  DNSAddress.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3: the `IPAddress` return type sketched in the phase
//  brief, named `DNSAddress` here to avoid colliding with any
//  `Foundation`/platform type of a similar name. A deliberately minimal
//  value type over raw address bytes -- not a wrapper around NIOCore's
//  `SocketAddress`, because `SocketAddress` always carries a port and a
//  resolved-hostname string that make no sense for a bare A/AAAA record;
//  the transport-layer consumer (`DirectMXTransport`) is expected to
//  combine one of these with a port via
//  `SocketAddress(ipAddress: address.description, port: ...)` once it knows
//  which port it's connecting on -- that composition is a transport
//  decision, not this resolver's.
//

/// A raw IPv4 or IPv6 address, as decoded from an A/AAAA resource record.
/// No port, no hostname -- just the address bytes plus a
/// `CustomStringConvertible` rendering suitable for feeding straight into
/// `NIOCore.SocketAddress(ipAddress:port:)`.
public enum DNSAddress: Sendable, Hashable {
    /// Exactly 4 bytes, network byte order (as they appeared in the A
    /// record's RDATA).
    case v4([UInt8])
    /// Exactly 16 bytes, network byte order (as they appeared in the AAAA
    /// record's RDATA).
    case v6([UInt8])
}

extension DNSAddress {
    /// `false` for any address that isn't a globally reachable unicast
    /// address -- the addresses a caller resolving an *untrusted* hostname
    /// (e.g. `DirectMXTransport` resolving a recipient-controlled domain's
    /// MX/A/AAAA records) must not dial. See
    /// `DirectMXConfig.allowPrivateAddresses` for where this is applied and
    /// its opt-out.
    ///
    /// IPv4 rejects every block in the IANA IPv4 Special-Purpose Address
    /// Registry that isn't globally reachable, plus multicast and the
    /// reserved space: `0.0.0.0/8` ("this network"; `0.0.0.0` reaches the
    /// local host on most systems), `10.0.0.0/8`, `100.64.0.0/10`,
    /// `127.0.0.0/8`, `169.254.0.0/16` (including cloud metadata),
    /// `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`,
    /// `192.168.0.0/16`, `198.18.0.0/15` (benchmarking), `198.51.100.0/24`,
    /// `203.0.113.0/24`, `224.0.0.0/4` (multicast) and `240.0.0.0/4`
    /// (reserved, including broadcast).
    ///
    /// IPv6 is an allow-list: only global unicast `2000::/3` passes, so
    /// `::`, `::1`, IPv4-compatible `::a.b.c.d`, `100::/64`, `fc00::/7`,
    /// `fe80::/10`, `fec0::/10`, `ff00::/8` and every other block outside it
    /// are rejected. Inside it, `2001::/23` (IETF protocol assignments,
    /// including Teredo and benchmarking), `2001:db8::/32` and `3fff::/20`
    /// (documentation) are rejected too. Addresses that embed an IPv4
    /// address are judged by it: IPv4-mapped `::ffff:a.b.c.d`, the NAT64
    /// well-known prefix `64:ff9b::/96` (the local-use `64:ff9b:1::/48` is
    /// rejected), and 6to4 `2002::/16`. Without that, publishing an AAAA
    /// record for `::ffff:127.0.0.1` or `2002:7f00:1::` would bypass every
    /// IPv4 check.
    public var isRoutable: Bool {
        switch self {
        case .v4(let bytes):
            return Self.isRoutableIPv4(bytes)
        case .v6(let bytes):
            return Self.isRoutableIPv6(bytes)
        }
    }

    private static func isRoutableIPv4(_ b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        switch b[0] {
        case 0: return false // 0.0.0.0/8 -- "this network"
        case 10: return false // 10.0.0.0/8 -- RFC 1918
        case 100 where (64...127).contains(b[1]): return false // 100.64.0.0/10 -- RFC 6598 shared/CGNAT
        case 127: return false // 127.0.0.0/8 -- loopback
        case 169 where b[1] == 254: return false // 169.254.0.0/16 -- link-local
        case 172 where (16...31).contains(b[1]): return false // 172.16.0.0/12 -- RFC 1918
        case 192 where b[1] == 0 && b[2] == 0: return false // 192.0.0.0/24 -- IETF protocol assignments
        case 192 where b[1] == 0 && b[2] == 2: return false // 192.0.2.0/24 -- TEST-NET-1
        case 192 where b[1] == 88 && b[2] == 99: return false // 192.88.99.0/24 -- 6to4 relay anycast (deprecated)
        case 192 where b[1] == 168: return false // 192.168.0.0/16 -- RFC 1918
        case 198 where b[1] == 18 || b[1] == 19: return false // 198.18.0.0/15 -- benchmarking
        case 198 where b[1] == 51 && b[2] == 100: return false // 198.51.100.0/24 -- TEST-NET-2
        case 203 where b[1] == 0 && b[2] == 113: return false // 203.0.113.0/24 -- TEST-NET-3
        case 224...255: return false // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255
        default: return true
        }
    }

    private static func isRoutableIPv6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        // ::ffff:a.b.c.d -- IPv4-mapped (RFC 4291 §2.5.5.2).
        if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF {
            return isRoutableIPv4(Array(b[12..<16]))
        }
        // 64:ff9b::/96 -- NAT64 well-known prefix (RFC 6052): judged by the
        // embedded IPv4 address.
        if b[0] == 0x00, b[1] == 0x64, b[2] == 0xFF, b[3] == 0x9B, b[4..<12].allSatisfy({ $0 == 0 }) {
            return isRoutableIPv4(Array(b[12..<16]))
        }
        // Allow-list: global unicast 2000::/3 only.
        guard (b[0] & 0xE0) == 0x20 else { return false }
        // 2001::/23 -- IETF protocol assignments (Teredo, benchmarking, ORCHID...).
        if b[0] == 0x20, b[1] == 0x01, b[2] < 0x02 { return false }
        // 2001:db8::/32 -- documentation.
        if b[0] == 0x20, b[1] == 0x01, b[2] == 0x0D, b[3] == 0xB8 { return false }
        // 2002::/16 -- 6to4: judged by the embedded IPv4 address.
        if b[0] == 0x20, b[1] == 0x02 { return isRoutableIPv4(Array(b[2..<6])) }
        // 3fff::/20 -- documentation (RFC 9637).
        if b[0] == 0x3F, b[1] == 0xFF, (b[2] & 0xF0) == 0x00 { return false }
        return true
    }
}

extension DNSAddress: CustomStringConvertible {
    /// Dotted-quad for `.v4` (`"93.184.216.34"`), full (uncompressed,
    /// lowercase-hex) colon-hextet form for `.v6`
    /// (`"2606:2800:220:1:248:1893:25c8:1946"`). The uncompressed `.v6`
    /// form is deliberately not RFC 5952-canonical (no `::` run
    /// compression) -- it's unambiguous and trivially correct to produce
    /// without a compression-run-finding algorithm, and `SocketAddress`'s
    /// own parser accepts uncompressed input just as readily as compressed.
    public var description: String {
        switch self {
        case .v4(let bytes):
            return bytes.map(String.init).joined(separator: ".")
        case .v6(let bytes):
            var hextets: [String] = []
            hextets.reserveCapacity(8)
            var index = 0
            while index < 16 {
                let value = UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
                hextets.append(String(value, radix: 16))
                index += 2
            }
            return hextets.joined(separator: ":")
        }
    }
}

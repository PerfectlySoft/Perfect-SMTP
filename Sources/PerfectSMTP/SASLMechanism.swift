//
//  SASLMechanism.swift
//  PerfectSMTP
//
//  AUTH abstraction (plan §4.5). `SASLPlain`/`SASLLogin` are the workhorses
//  (SendGrid/Postmark/SES issue API keys as SMTP passwords); `XOAuth2` is
//  first-class and mandatory-in-practice for Gmail/Workspace (legacy SMTP
//  password auth disabled since March 2025) and Microsoft 365 (Basic-auth
//  SMTP being phased out through 2027). `SASLCramMD5`/`SASLScramSHA256` are
//  deliberately not implemented — deferred per plan §4.5/§10.
//

import Foundation

/// A SASL mechanism's message-exchange state machine, driven by
/// `SMTPConnection.authenticate(_:)` during `AUTH`. Implement this to add a
/// mechanism beyond the three built-in ones (`SASLPlain`/`SASLLogin`/
/// `XOAuth2`); `SMTPConnection` calls these methods in a fixed order and
/// doesn't need to know which concrete mechanism it's driving.
///
/// Exchange shape: `initialResponse()` is called exactly once, before the
/// first `AUTH <name>` command is even sent -- returning non-`nil` sends it
/// as the (optional, RFC 4954) inline initial-response argument on that same
/// command line; returning `nil` (as `SASLLogin` does) sends a bare
/// `AUTH <name>` with no inline argument, and the server's first `334`
/// challenge is handled by `respond(to:)` instead. After that,
/// `SMTPConnection.authenticate(_:)`'s exchange loop calls `respond(to:)`
/// once per `334` continuation reply the server sends, purely driven by the
/// server's own reply codes -- it stops once the server issues a final,
/// non-`334` reply (`235` success or a `5xx`/`4xx` failure), not by
/// consulting `isComplete`.
public protocol SASLMechanism: Sendable {
    /// The `AUTH` command's mechanism name (e.g. `"PLAIN"`, `"LOGIN"`,
    /// `"XOAUTH2"`), sent verbatim as `AUTH <name>`.
    var name: String { get }
    /// The RFC 4954 inline initial response, sent base64-encoded on the same
    /// line as `AUTH <name>` when non-`nil`. Return `nil` for a mechanism
    /// that has nothing to say before seeing the server's first challenge
    /// (e.g. `SASLLogin`).
    mutating func initialResponse() async throws -> [UInt8]?
    /// Computes this mechanism's response to one base64-decoded `334`
    /// challenge from the server. May be `async`-suspending (`XOAuth2` uses
    /// this to `await` its `tokenProvider` closure).
    mutating func respond(to challenge: [UInt8]) async throws -> [UInt8]
    /// Whether this mechanism considers its own step sequence finished.
    /// Exposed for the mechanism's own bookkeeping/introspection --
    /// `SMTPConnection.authenticate(_:)`'s exchange loop does not currently
    /// consult this property itself; it terminates purely on the server's
    /// reply code (see this protocol's own doc comment).
    var isComplete: Bool { get }
}

/// RFC 4616. `authzid` is almost always empty for SMTP AUTH (the
/// authentication identity and authorization identity are the same
/// mailbox); exposed for completeness.
public struct SASLPlain: SASLMechanism {
    public let name = "PLAIN"
    public let authzid: String
    public let username: String
    public let password: String
    private var sentInitial = false

    public init(authzid: String = "", username: String, password: String) {
        self.authzid = authzid
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        var bytes: [UInt8] = []
        bytes.append(contentsOf: Array(authzid.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(username.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(password.utf8))
        return bytes
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // PLAIN's whole exchange is the initial response; a server that
        // still issues a mid-exchange continuation gets an empty reply.
        []
    }

    public var isComplete: Bool { sentInitial }
}

/// RFC 4954's `AUTH LOGIN` (a de facto standard, not itself an RFC-defined
/// SASL mechanism, but universally supported). No initial response; the
/// server issues two base64 `334` challenges ("Username:" then
/// "Password:") in order.
public struct SASLLogin: SASLMechanism {
    public let name = "LOGIN"
    public let username: String
    public let password: String
    private var step = 0

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? { nil }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        step += 1
        return step == 1 ? Array(username.utf8) : Array(password.utf8)
    }

    public var isComplete: Bool { step >= 2 }
}

/// RFC 7628 XOAUTH2/OAUTHBEARER framing:
/// `user=<username>\x01auth=Bearer <token>\x01\x01`. The library only
/// formats this framing and invokes the caller-supplied `tokenProvider` —
/// it does not itself run an OAuth2 authorization flow. On a `535`, the
/// connection-level `authenticate(_:)` calls `tokenProvider()` again and
/// retries the whole exchange once (plan §4.5) before surfacing
/// `SMTPError.authenticationFailed`.
public struct XOAuth2: SASLMechanism {
    public let name = "XOAUTH2"
    public let username: String
    public let tokenProvider: @Sendable () async throws -> String
    private var sentInitial = false

    public init(username: String, tokenProvider: @escaping @Sendable () async throws -> String) {
        self.username = username
        self.tokenProvider = tokenProvider
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        let token = try await tokenProvider()
        let framed = "user=\(username)\u{1}auth=Bearer \(token)\u{1}\u{1}"
        return Array(framed.utf8)
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // A `334` here is Google's XOAUTH2 error-detail continuation (a
        // base64 JSON error object); RFC 7628 §3.2.3 requires responding
        // with an empty message so the server then returns its real 5xx,
        // which `authenticate(_:)`'s exchange loop classifies normally.
        []
    }

    public var isComplete: Bool { sentInitial }
}

// Redacted descriptions, so interpolating a mechanism or a relay
// configuration into a log line or error message (`"\(config)"`) never
// prints a password. Without these, Swift's default reflection-based
// description prints every stored property, password included. Same
// discipline as `SigningKey`'s redacted description.
extension SASLPlain: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SASLPlain(username: \(username), password: <redacted>)" }
    public var debugDescription: String { description }
}

extension SASLLogin: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SASLLogin(username: \(username), password: <redacted>)" }
    public var debugDescription: String { description }
}

extension RelayConfig.Auth: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        switch self {
        case .none: return "none"
        case .plain(let username, _): return "plain(username: \(username), password: <redacted>)"
        case .login(let username, _): return "login(username: \(username), password: <redacted>)"
        case .xoauth2(let username, _): return "xoauth2(username: \(username), tokenProvider: <redacted>)"
        }
    }

    public var debugDescription: String { description }
}

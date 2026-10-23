//
//  RelayTransport.swift
//  PerfectSMTP
//
//  Plan §3/§4.2: network handoff to an already-operated MTA — scope
//  explicitly includes both commercial ESPs (SendGrid/Postmark/SES, with
//  AUTH) and self-hosted/internal MTAs reachable over the network
//  (possibly with no AUTH at all, on a trusted network). Same NIO-based
//  client either way, just configuration; owns a `SMTPConnectionPool`
//  keyed to one configured host.
//

import NIOCore

public struct RelayConfig: Sendable {
    public enum Auth: Sendable {
        case none
        case plain(username: String, password: String)
        case login(username: String, password: String)
        case xoauth2(username: String, tokenProvider: @Sendable () async throws -> String)
    }

    public var host: String
    public var port: Int
    public var tls: TLSMode
    public var auth: Auth
    public var ehloHostname: String
    public var pool: SMTPConnectionPool.Configuration
    /// Whether `auth` may be sent over a connection with `tls: .none`.
    /// `false` (the default) makes `RelayTransport.send` throw
    /// `RelayTransportError.authenticationRequiresTLS` instead of sending
    /// credentials or tokens in cleartext. Set it only for a relay on a
    /// network you trust (a loopback MTA, a test server).
    public var allowsAuthenticationWithoutTLS: Bool

    public init(
        host: String,
        port: Int,
        tls: TLSMode,
        auth: Auth = .none,
        ehloHostname: String = "localhost",
        pool: SMTPConnectionPool.Configuration = .init(),
        allowsAuthenticationWithoutTLS: Bool = false
    ) {
        self.host = host
        self.port = port
        self.tls = tls
        self.auth = auth
        self.ehloHostname = ehloHostname
        self.pool = pool
        self.allowsAuthenticationWithoutTLS = allowsAuthenticationWithoutTLS
    }

    var mechanism: (any SASLMechanism)? {
        switch auth {
        case .none: return nil
        case .plain(let username, let password): return SASLPlain(username: username, password: password)
        case .login(let username, let password): return SASLLogin(username: username, password: password)
        case .xoauth2(let username, let tokenProvider): return XOAuth2(username: username, tokenProvider: tokenProvider)
        }
    }
}

/// Configuration errors `RelayTransport.send(_:_:)` throws before opening
/// any connection.
public enum RelayTransportError: Error, Sendable, Equatable {
    /// `RelayConfig.auth` is set but `tls` is `.none`, and
    /// `allowsAuthenticationWithoutTLS` is `false`: authenticating would
    /// send the credentials in cleartext.
    case authenticationRequiresTLS
}

/// A `SMTPTransport` that submits to one configured SMTP host via a pooled,
/// possibly-authenticated connection. `RelayTransport` owns its pool; each
/// `send(_:_:)` call checks out a connection, authenticates it once (pool
/// connections are dialed already-EHLO'd — see `SMTPConnectionPool`'s
/// dialer — so only AUTH remains here, and only on a freshly-dialed
/// connection, tracked via the pool's own connection reuse), and hands the
/// transaction to `SMTPConnection.sendMessage(_:_:)`.
public final class RelayTransport: SMTPTransport, Sendable {
    private let config: RelayConfig
    private let pool: SMTPConnectionPool
    private let key: SMTPConnectionPool.Key

    /// - Parameters:
    ///   - config: The relay host/port/TLS/auth to send through. Every
    ///     `send(_:_:)` call on this transport goes to this one configured
    ///     destination.
    ///   - group: The `EventLoopGroup` this transport's connection pool and
    ///     every connection it dials run on. Not owned by this transport --
    ///     the caller is responsible for its lifecycle.
    public init(config: RelayConfig, group: any EventLoopGroup) {
        self.config = config
        self.pool = SMTPConnectionPool(configuration: config.pool, ehloHostname: config.ehloHostname, group: group)
        self.key = SMTPConnectionPool.Key(host: config.host, port: config.port, tls: config.tls)
    }

    /// Test/internal-only initializer: overrides the pool's dialer
    /// entirely, mirroring `SMTPConnectionPool`'s and `DirectMXTransport`'s
    /// own test seams -- lets pool-health regression tests (e.g. for the
    /// `isHealthy:`/circuit-breaker fix above) script a connection's
    /// transaction outcome without a real socket.
    init(config: RelayConfig, group: any EventLoopGroup, dialer: @escaping @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection) {
        self.config = config
        self.pool = SMTPConnectionPool(configuration: config.pool, group: group, dialer: dialer)
        self.key = SMTPConnectionPool.Key(host: config.host, port: config.port, tls: config.tls)
    }

    /// Checks out a pooled connection to `config.host`, authenticating it
    /// first if it's freshly dialed and `config.auth` isn't `.none`, then
    /// runs one mail transaction against it. `RelayTransport` never
    /// auto-retries a transient failure itself -- a `.queuedForRetry`
    /// `DeliveryResult` reflects the server's own reply classification, but
    /// nothing here schedules a redelivery attempt (unlike
    /// `DirectMXTransport`, which owns a retry queue); see
    /// `Documentation/user-guide.md`'s "Handling delivery results and
    /// retries" section for what that means for callers.
    public func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        if config.tls == .none, config.mechanism != nil, !config.allowsAuthenticationWithoutTLS {
            throw RelayTransportError.authenticationRequiresTLS
        }
        // FIX (milestone architecture + SMTP-protocol reviews, originally
        // flagged against `DirectMXTransport.attemptOnHost` but confirmed
        // to apply equally here): `SMTPConnection.sendMessage` returns
        // RCPT/DATA-phase rejections as normal `[DeliveryResult]` data,
        // never throws them (only a MAIL-FROM-level rejection throws, and
        // that already flows through `withConnection`'s `catch` ->
        // `healthy: false` unmodified). Without `isHealthy:` here, a
        // mid-DATA disconnect (`.ambiguous`) or a `421` in the RCPT/DATA
        // phase would return normally from this closure and be treated as
        // `healthy: true` -- the same gap the architecture/SMTP-protocol
        // reviews found in `DirectMXTransport`, reachable here too since
        // both transports share this same `withConnection`-wrapping shape.
        // `RelayTransport` has no host-fallback to break, but it still
        // owns a pool and a circuit breaker whose bookkeeping deserves to
        // be correct.
        return try await pool.withConnection(to: key, isHealthy: SMTPConnectionPool.deliveryResultsIndicateHealthyConnection) { connection in
            // A pooled connection is reused across many checkouts; only
            // authenticate once per connection (most servers reject a
            // second AUTH on an already-authenticated session).
            if !connection.isAuthenticated, let mechanism = self.config.mechanism {
                try await connection.authenticate(mechanism)
            }
            return try await connection.sendMessage(envelope, message)
        }
    }

    /// Closes every pooled connection to `config.host`. Call this when
    /// you're done sending through this transport -- it does not close the
    /// `EventLoopGroup` it was constructed with, only the connections this
    /// transport itself opened.
    public func shutdown() async {
        await pool.shutdown()
    }
}

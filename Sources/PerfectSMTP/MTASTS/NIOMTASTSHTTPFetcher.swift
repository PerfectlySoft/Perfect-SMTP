//
//  NIOMTASTSHTTPFetcher.swift
//  PerfectSMTP
//
//  Release review: the MTA-STS policy fetch must not buffer an unbounded
//  body. `URLSessionMTASTSFetcher` enforces the 64 KiB cap while
//  streaming, which holds on Darwin, but on Linux corelibs Foundation keeps
//  reading (and queueing) data after the task is cancelled: in the
//  endless-body test on linux/amd64 the process reached 5.9 GB RSS and was
//  OOM-killed in 6 of 15 runs. This fetcher speaks HTTP/1.1 itself over
//  SwiftNIO (already a dependency; NIOHTTP1 is part of swift-nio), so it
//  stops reading the moment the cap is hit, on every platform. It is
//  `MTASTSPolicyManager`'s default fetcher.
//

import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS

/// Fetches MTA-STS policy files with a plain HTTP/1.1 GET over SwiftNIO.
///
/// - **Address vetting (SSRF):** the host is resolved once, through
///   `addressResolver` (default: this library's `DNSResolver`), every
///   address is checked with `DNSAddress.isRoutable`, and the connection is
///   made to a vetted address, so what was checked is what is dialed. The
///   name still goes in SNI and `Host`. With no permitted address the fetch
///   throws `MTASTSHTTPFetchError.noPermittedAddress` without connecting.
///   `allowPrivateAddresses` turns this off (tests, internal setups).
/// - **TLS** uses `tlsConfiguration` (default: full certificate
///   verification against the system trust store). For a host name, the
///   certificate must also carry a DNS subjectAltName for it: NIOSSL alone
///   accepts an IP SAN equal to the dialed address (release review). An
///   `http://` URL (tests, local tooling) is fetched in the clear.
/// - Redirects are never followed (RFC 8461 §3.3): a 3xx is returned as
///   is, and `MTASTSPolicyManager` treats any non-200 as a failed fetch.
/// - `timeout` bounds the whole fetch, resolution to last byte
///   (`MTASTSHTTPFetchError.timedOut`), and cancelling the calling task
///   ends it at once (`CancellationError`); either way the connection is
///   closed.
/// - At most `maximumBodySize` body bytes are read. A larger
///   `Content-Length` is refused before the body, and the connection is
///   closed as soon as the cap is passed
///   (`MTASTSHTTPFetchError.responseTooLarge`).
/// - Once a fetch is done (or capped, timed out, refused) it stops reading
///   and closes without waiting for the server's TLS close_notify
///   (`tlsConfiguration.shutdownTimeout` is overridden). The response is
///   still accepted only when complete: by `Content-Length`, the chunked
///   terminator, or, for a body delimited by the close, the server's
///   close_notify (over `http://`, which is for tests and local tooling,
///   a bare TCP close ends such a body).
public struct NIOMTASTSHTTPFetcher: MTASTSHTTPFetching {
    private let group: any EventLoopGroup
    private let timeout: TimeInterval
    private let maximumBodySize: Int
    private let tlsConfiguration: TLSConfiguration
    private let addressResolver: any MTASTSAddressResolving
    private let allowPrivateAddresses: Bool

    public init(
        group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        timeout: TimeInterval = 60,
        maximumBodySize: Int = MTASTSPolicyManager.maximumPolicyResponseSizeBytes,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration(),
        addressResolver: (any MTASTSAddressResolving)? = nil,
        allowPrivateAddresses: Bool = false
    ) {
        self.group = group
        self.timeout = timeout
        self.maximumBodySize = max(0, maximumBodySize)
        self.tlsConfiguration = tlsConfiguration
        self.addressResolver = addressResolver ?? DNSResolver(group: group)
        self.allowPrivateAddresses = allowPrivateAddresses
    }

    public enum FetchError: Error, Sendable, Equatable {
        /// Only `http` and `https` URLs with a host are fetched.
        case unsupportedURL(String)
        /// The connection closed before a complete response arrived.
        case incompleteResponse
    }

    public func fetch(url: URL) async throws -> MTASTSHTTPResponse {
        guard let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let rawHost = url.host, !rawHost.isEmpty
        else { throw FetchError.unsupportedURL(url.absoluteString) }
        let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]") ? String(rawHost.dropFirst().dropLast()) : rawHost
        let useTLS = scheme == "https"
        let port = url.port ?? (useTLS ? 443 : 80)
        // 6.0.1: the request target is the URL's own percent-encoded path
        // and query. `url.path` is percent-decoded and drops a trailing
        // slash, so `/a%20b/` went out as `/a b` (a malformed request line)
        // and `/%3F` as `/?`. The policy manager's fixed
        // `/.well-known/mta-sts.txt` was never affected; direct callers were.
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let encodedPath = components?.percentEncodedPath ?? ""
        let basePath = encodedPath.isEmpty ? "/" : encodedPath
        let path = components?.percentEncodedQuery.map { basePath + "?" + $0 } ?? basePath
        let literal = Self.addressLiteral(host)
        // Host header: name or address, IPv6 in brackets, port if explicit.
        let hostField = (literal.map { if case .v6 = $0 { return "[\(host)]" } else { return host } } ?? host)
            + (url.port.map { ":\($0)" } ?? "")

        let limit = maximumBodySize
        // 6.0.1: when we close (done, capped, timed out, refused), don't
        // wait for the peer's close_notify. NIOSSL's clean shutdown keeps
        // reading, and discarding, whatever the peer sends for up to
        // `shutdownTimeout` (5 s by default): against an endless body that
        // ignores our close_notify, 5 s of full-speed reading per capped
        // fetch. This only affects our own close, after the response has
        // been accepted or refused.
        var tls = tlsConfiguration
        tls.shutdownTimeout = .milliseconds(1)
        let sslContext = useTLS ? try NIOSSLContext(configuration: tls) : nil
        let connectTimeout = Self.timeAmount(timeout)
        let resolver = addressResolver
        let allowPrivate = allowPrivateAddresses
        // One event loop for the whole fetch: its state, every promise and
        // every attempt's channel live there.
        let loop = group.next()
        let promise = loop.makePromise(of: MTASTSHTTPResponse.self)
        let abortSignal = loop.makePromise(of: Void.self)
        let state = NIOLoopBoundBox.makeBoxSendingValue(FetchState(), as: FetchState.self, eventLoop: loop)

        // 6.0.1 (review): the deadline used to fail only the response
        // promise, so a server that accepted and never finished the TLS
        // handshake held the fetch (and its fd) past the deadline, and a
        // cancelled caller waited for the server. Now the deadline and
        // cancellation abort every stage (resolution, connect, handshake,
        // response), and the channel, even one that connects later, is
        // closed.
        let abort: @Sendable (any Error) -> Void = { error in
            loop.execute {
                if state.value.aborted == nil { state.value.aborted = error }
                abortSignal.fail(error)
                promise.fail(error)
                if let channel = state.value.channel { Self.abandon(channel) }
            }
        }
        let deadline = loop.scheduleTask(in: connectTimeout) { abort(MTASTSHTTPFetchError.timedOut) }
        defer {
            deadline.cancel()
            // Every promise is completed on every path (a no-op if it
            // already was): a leaked promise traps in debug builds.
            abortSignal.succeed(())
            promise.fail(FetchError.incompleteResponse)
        }
        let aborted = abortSignal.futureResult
        func abortReason() async -> (any Error)? {
            try? await loop.submit { state.value.aborted }.get()
        }

        return try await withTaskCancellationHandler {
            do {
                // Resolve once and vet; the vetted address is what gets dialed.
                let resolved: [DNSAddress]
                if let literal {
                    resolved = [literal]
                } else {
                    let resolving = loop.makePromise(of: [DNSAddress].self)
                    let task = Task {
                        do { resolving.succeed(try await resolver.resolveAddresses(hostname: host)) } catch { resolving.fail(error) }
                    }
                    defer { task.cancel() }
                    resolved = try await Self.unlessAborted(resolving.futureResult, aborted)
                }
                let permitted = allowPrivate ? resolved : resolved.filter(\.isRoutable)
                guard !permitted.isEmpty else { throw MTASTSHTTPFetchError.noPermittedAddress(host: host) }

                func bootstrap(ready: EventLoopPromise<Void>) -> ClientBootstrap {
                    ClientBootstrap(group: loop)
                        .connectTimeout(connectTimeout)
                        .channelInitializer { channel in
                            channel.eventLoop.makeCompletedFuture {
                                if let sslContext {
                                    let tls = try NIOSSLClientHandler(context: sslContext, serverHostname: literal == nil ? host : nil)
                                    try channel.pipeline.syncOperations.addHandler(tls)
                                    try channel.pipeline.syncOperations.addHandler(
                                        TLSReadyGate(host: literal == nil ? host : nil, ready: ready)
                                    )
                                }
                                try channel.pipeline.syncOperations.addHTTPClientHandlers()
                                try channel.pipeline.syncOperations.addHandler(CappedResponseCollector(limit: limit, promise: promise))
                            }
                        }
                }
                var connected: (channel: any Channel, ready: EventLoopPromise<Void>)?
                var lastError: any Error = MTASTSHTTPFetchError.noPermittedAddress(host: host)
                for address in permitted {
                    // Each attempt's readiness promise is created up front and
                    // held here rather than looked up in a pipeline that may
                    // already have been torn down.
                    let ready = loop.makePromise(of: Void.self)
                    let attempt = loop.makePromise(of: (any Channel).self)
                    do {
                        // A channel that connects after an abort is closed;
                        // otherwise it is recorded, so an abort closes it.
                        bootstrap(ready: ready).connect(to: try SocketAddress(ipAddress: address.description, port: port))
                            .hop(to: loop).whenComplete { result in
                                switch result {
                                case .success(let channel):
                                    if let error = state.value.aborted {
                                        Self.abandon(channel)
                                        attempt.fail(error)
                                    } else {
                                        state.value.channel = channel
                                        attempt.succeed(channel)
                                    }
                                case .failure(let error):
                                    attempt.fail(error)
                                }
                            }
                        connected = (try await Self.unlessAborted(attempt.futureResult, aborted), ready)
                        break
                    } catch {
                        ready.fail(error)  // no-op if the gate already failed it
                        attempt.fail(error)
                        if let reason = await abortReason() { throw reason }
                        lastError = error
                    }
                }
                guard let (channel, ready) = connected else { throw lastError }
                // Re-review: nothing is written until the handshake has
                // completed and the certificate's DNS name has been checked,
                // so a refused server never sees the request.
                if useTLS {
                    try await Self.unlessAborted(ready.futureResult, aborted)
                } else {
                    ready.succeed(())
                }
                var headers = HTTPHeaders()
                headers.add(name: "Host", value: hostField)
                headers.add(name: "User-Agent", value: "PerfectSMTP-MTA-STS")
                headers.add(name: "Accept", value: "text/plain")
                headers.add(name: "Connection", value: "close")
                let head = HTTPRequestHead(version: .http1_1, method: .GET, uri: path, headers: headers)
                // Written on the loop, and only if nothing has aborted the fetch.
                try await loop.submit {
                    if let error = state.value.aborted { throw error }
                    channel.write(HTTPClientRequestPart.head(head), promise: nil)
                    channel.writeAndFlush(HTTPClientRequestPart.end(nil), promise: nil)
                }.get()
                let response = try await promise.futureResult.get()
                Self.abandon(channel)
                return response
            } catch {
                let reason = await abortReason() ?? error
                abort(reason)  // fails what is still pending and closes the channel
                throw reason
            }
        } onCancel: {
            abort(CancellationError())
        }
    }

    /// `future`'s result, or the abort's error if the fetch is aborted first.
    private static func unlessAborted<T: Sendable>(_ future: EventLoopFuture<T>, _ aborted: EventLoopFuture<Void>) async throws -> T {
        let either = aborted.eventLoop.makePromise(of: T.self)
        future.hop(to: aborted.eventLoop).whenComplete { either.completeWith($0) }
        aborted.whenFailure { either.fail($0) }
        return try await either.futureResult.get()
    }

    /// Stops reading, then closes: no new reads are started while the
    /// close (and the 1 ms TLS shutdown) completes.
    static func abandon(_ channel: any Channel) {
        channel.eventLoop.execute {
            try? channel.syncOptions?.setOption(.autoRead, value: false)
            channel.close(promise: nil)
        }
    }

    /// `host` as an address if it is an IP literal.
    static func addressLiteral(_ host: String) -> DNSAddress? {
        guard let address = try? SocketAddress(ipAddress: host, port: 0) else { return nil }
        switch address {
        case .v4(let v4):
            return .v4(withUnsafeBytes(of: v4.address.sin_addr) { Array($0) })
        case .v6(let v6):
            return .v6(withUnsafeBytes(of: v6.address.sin6_addr) { Array($0) })
        default:
            return nil
        }
    }

    private static func timeAmount(_ seconds: TimeInterval) -> TimeAmount {
        .nanoseconds(Int64(min(max(0, seconds), 86_400) * 1_000_000_000))
    }
}

/// Per-fetch state, confined to the fetch's event loop.
private struct FetchState: Sendable {
    var channel: (any Channel)?
    var aborted: (any Error)?
}

/// Completes `ready` once the TLS handshake is done and, for a host name,
/// the verified certificate carries a matching DNS subjectAltName; fails
/// it (and closes) otherwise. The request is written only after `ready`
/// succeeds. Event-loop confined.
private final class TLSReadyGate: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    private let host: String?
    let ready: EventLoopPromise<Void>

    init(host: String?, ready: EventLoopPromise<Void>) {
        self.host = host
        self.ready = ready
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let tlsEvent = event as? TLSUserEvent, case .handshakeCompleted = tlsEvent {
            do {
                if let host { try CertificateDNSNames.requireMatch(in: context.pipeline.syncOperations, host: host) }
                ready.succeed(())
            } catch {
                ready.fail(error)
                context.fireErrorCaught(error)
                try? context.channel.syncOptions?.setOption(.autoRead, value: false)
                context.close(promise: nil)
                return
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        ready.fail(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        ready.fail(NIOMTASTSHTTPFetcher.FetchError.incompleteResponse)
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        ready.fail(NIOMTASTSHTTPFetcher.FetchError.incompleteResponse)
    }
}

/// Collects one HTTP response, failing (and closing) as soon as the body
/// would pass `limit`. Event-loop confined: all callbacks run on the
/// channel's loop, which is why `@unchecked Sendable` holds.
private final class CappedResponseCollector: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart
    typealias OutboundIn = HTTPClientRequestPart
    typealias OutboundOut = HTTPClientRequestPart

    private let limit: Int
    private let promise: EventLoopPromise<MTASTSHTTPResponse>
    private var status: Int?
    private var contentType: String?
    private var body: [UInt8] = []
    private var done = false

    init(limit: Int, promise: EventLoopPromise<MTASTSHTTPResponse>) {
        self.limit = limit
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !done else { return }
        switch Self.unwrapInboundIn(data) {
        case .head(let head):
            // A 1xx interim response is followed by the real one.
            guard head.status.code >= 200 else { return }
            if let length = head.headers.first(name: "Content-Length").flatMap(Int.init), length > limit {
                finish(context, .failure(MTASTSHTTPFetchError.responseTooLarge(limit: limit)))
                return
            }
            status = Int(head.status.code)
            contentType = head.headers.first(name: "Content-Type")
        case .body(var buffer):
            guard status != nil else { return }
            if body.count + buffer.readableBytes > limit {
                finish(context, .failure(MTASTSHTTPFetchError.responseTooLarge(limit: limit)))
                return
            }
            body.append(contentsOf: buffer.readBytes(length: buffer.readableBytes) ?? [])
        case .end:
            guard let status else { return }
            finish(context, .success(MTASTSHTTPResponse(statusCode: status, contentType: contentType, body: body)))
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish(context, .failure(NIOMTASTSHTTPFetcher.FetchError.incompleteResponse))
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        finish(context, .failure(error))
    }

    /// 6.0.1 (review): any close that passes here before the response is
    /// complete fails it first. A close that ends through NIOSSL's shutdown
    /// timer (now 1 ms) leaves no `uncleanShutdown` error behind, so the
    /// decoder would otherwise end a close-delimited body as if the server
    /// had. Every close of ours already settles the response first; this
    /// covers any other (say, the event-loop group shutting down).
    func close(context: ChannelHandlerContext, mode: CloseMode, promise closePromise: EventLoopPromise<Void>?) {
        if !done {
            done = true
            body = []
            promise.fail(NIOMTASTSHTTPFetcher.FetchError.incompleteResponse)
        }
        context.close(mode: mode, promise: closePromise)
    }

    private func finish(_ context: ChannelHandlerContext, _ result: Result<MTASTSHTTPResponse, any Error>) {
        guard !done else { return }
        done = true
        body = []
        promise.completeWith(result)
        try? context.channel.syncOptions?.setOption(.autoRead, value: false)
        context.close(promise: nil)
    }
}

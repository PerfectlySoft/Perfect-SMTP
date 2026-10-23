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

/// Fetches MTA-STS policy files with a plain HTTP/1.1 GET over SwiftNIO.
///
/// - TLS uses `tlsConfiguration` (default: full certificate verification
///   against the system trust store) with the URL's host as SNI and
///   expected name; an `http://` URL (tests, local tooling) is fetched in
///   the clear.
/// - Redirects are never followed (RFC 8461 §3.3): a 3xx is returned as
///   is, and `MTASTSPolicyManager` treats any non-200 as a failed fetch.
/// - `timeout` bounds the whole fetch, connect to last byte
///   (`MTASTSHTTPFetchError.timedOut`).
/// - At most `maximumBodySize` body bytes are read. A larger
///   `Content-Length` is refused before the body, and the connection is
///   closed as soon as the cap is passed
///   (`MTASTSHTTPFetchError.responseTooLarge`).
public struct NIOMTASTSHTTPFetcher: MTASTSHTTPFetching {
    private let group: any EventLoopGroup
    private let timeout: TimeInterval
    private let maximumBodySize: Int
    private let tlsConfiguration: TLSConfiguration

    public init(
        group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        timeout: TimeInterval = 60,
        maximumBodySize: Int = MTASTSPolicyManager.maximumPolicyResponseSizeBytes,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration()
    ) {
        self.group = group
        self.timeout = timeout
        self.maximumBodySize = max(0, maximumBodySize)
        self.tlsConfiguration = tlsConfiguration
    }

    public enum FetchError: Error, Sendable, Equatable {
        /// Only `http` and `https` URLs with a host are fetched.
        case unsupportedURL(String)
        /// The connection closed before a complete response arrived.
        case incompleteResponse
    }

    public func fetch(url: URL) async throws -> MTASTSHTTPResponse {
        guard let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = url.host, !host.isEmpty
        else { throw FetchError.unsupportedURL(url.absoluteString) }
        let useTLS = scheme == "https"
        let port = url.port ?? (useTLS ? 443 : 80)
        let basePath = url.path.isEmpty ? "/" : url.path
        let path = url.query.map { basePath + "?" + $0 } ?? basePath

        let limit = maximumBodySize
        let sslContext = useTLS ? try NIOSSLContext(configuration: tlsConfiguration) : nil
        let group = self.group
        let connectTimeout = Self.timeAmount(timeout)
        let promise = group.next().makePromise(of: MTASTSHTTPResponse.self)

        return try await Self.withDeadline(timeout, onTimeout: { promise.fail(MTASTSHTTPFetchError.timedOut) }) {
            let bootstrap = ClientBootstrap(group: group)
                .connectTimeout(connectTimeout)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        if let sslContext {
                            let isIPLiteral = (try? SocketAddress(ipAddress: host, port: 0)) != nil
                            let tls = try NIOSSLClientHandler(context: sslContext, serverHostname: isIPLiteral ? nil : host)
                            try channel.pipeline.syncOperations.addHandler(tls)
                        }
                        try channel.pipeline.syncOperations.addHTTPClientHandlers()
                        try channel.pipeline.syncOperations.addHandler(CappedResponseCollector(limit: limit, promise: promise))
                    }
                }
            let channel: any Channel
            do {
                channel = try await bootstrap.connect(host: host, port: port).get()
            } catch {
                promise.fail(error)
                throw error
            }
            var headers = HTTPHeaders()
            headers.add(name: "Host", value: url.port.map { "\(host):\($0)" } ?? host)
            headers.add(name: "User-Agent", value: "PerfectSMTP-MTA-STS")
            headers.add(name: "Accept", value: "text/plain")
            headers.add(name: "Connection", value: "close")
            let head = HTTPRequestHead(version: .http1_1, method: .GET, uri: path, headers: headers)
            channel.write(HTTPClientRequestPart.head(head), promise: nil)
            channel.writeAndFlush(HTTPClientRequestPart.end(nil), promise: nil)
            do {
                let response = try await promise.futureResult.get()
                channel.close(promise: nil)
                return response
            } catch {
                channel.close(promise: nil)
                throw error
            }
        }
    }

    private static func timeAmount(_ seconds: TimeInterval) -> TimeAmount {
        .nanoseconds(Int64(min(max(0, seconds), 86_400) * 1_000_000_000))
    }

    private static func withDeadline<T: Sendable>(
        _ seconds: TimeInterval, onTimeout: @escaping @Sendable () -> Void, _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { race in
            race.addTask { try await operation() }
            race.addTask {
                try await Task.sleep(nanoseconds: UInt64(min(max(0, seconds), 86_400) * 1_000_000_000))
                onTimeout()
                throw MTASTSHTTPFetchError.timedOut
            }
            defer { race.cancelAll() }
            guard let result = try await race.next() else { throw MTASTSHTTPFetchError.timedOut }
            return result
        }
    }
}

/// Collects one HTTP response, failing (and closing) as soon as the body
/// would pass `limit`. Event-loop confined: all callbacks run on the
/// channel's loop, which is why `@unchecked Sendable` holds.
private final class CappedResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart

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

    private func finish(_ context: ChannelHandlerContext, _ result: Result<MTASTSHTTPResponse, any Error>) {
        guard !done else { return }
        done = true
        body = []
        promise.completeWith(result)
        context.close(promise: nil)
    }
}

//
//  MTASTSHTTPFetching.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: the HTTPS fetch step of MTA-STS policy discovery (RFC
//  8461 §3.2 -- `GET https://mta-sts.<domain>/.well-known/mta-sts.txt`).
//
//  **Uses `Foundation.URLSession`, deliberately, not a hand-rolled or
//  NIO-based HTTP client** -- this matches this ecosystem's established
//  convention for simple, one-shot request/response HTTPS calls (Perfect-
//  FileMaker moved *off* PerfectCURL specifically to async/await
//  `URLSession` for exactly this kind of need; see
//  `Documentation/swift6-nio-rewrite-plan.md` §2's own citation of that
//  precedent). Building a second HTTP stack on top of swift-nio purely for
//  one GET request per (cache-miss) domain would be exactly the kind of
//  disproportionate engineering this plan's Phase 4 brief warns against --
//  MTA-STS's own fetch step has no pipelining, connection-pooling, or
//  streaming-body requirement that would justify it.
//
//  The fetch itself uses normal, fully-verified TLS: `URLSession`'s default
//  server-trust evaluation is never overridden or disabled anywhere in this
//  file -- an MTA-STS policy fetched over a connection with an invalid/
//  unverified certificate would be worse than useless (an attacker who can
//  MITM the HTTPS fetch could simply serve a permissive fake policy, or no
//  policy at all).
//
//  `MTASTSHTTPFetching` is the test seam (mirroring `MXResolving`'s and
//  `TXTResolving`'s pattern) that lets `MTASTSPolicyManagerCacheTests`
//  script fetch outcomes (success, 404, wrong content-type, network error)
//  without making a real network call.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One HTTPS response, reduced to exactly what MTA-STS policy fetching
/// needs (RFC 8461 §3.3: status code, `Content-Type`, and the body) --
/// deliberately not `URLResponse`/`Data` directly, so the test seam below
/// doesn't require a real `URLSession` round-trip to construct a fixture.
public struct MTASTSHTTPResponse: Sendable {
    public let statusCode: Int
    public let contentType: String?
    public let body: [UInt8]

    public init(statusCode: Int, contentType: String?, body: [UInt8]) {
        self.statusCode = statusCode
        self.contentType = contentType
        self.body = body
    }
}

/// The seam `MTASTSPolicyManager` fetches through -- `URLSessionMTASTSFetcher`
/// in production, a scripted fake in tests.
public protocol MTASTSHTTPFetching: Sendable {
    /// - Throws: Any error means "this fetch failed" as far as
    ///   `MTASTSPolicyManager` is concerned (network error, TLS failure,
    ///   timeout, DNS-for-the-HTTPS-hostname failure, etc.) -- it does not
    ///   need to distinguish failure modes beyond what `MTASTSHTTPResponse`
    ///   itself already communicates for a completed HTTP exchange (status
    ///   code, content type).
    func fetch(url: URL) async throws -> MTASTSHTTPResponse
}

/// Errors specific to this fetcher's own plumbing (as opposed to
/// `MTASTSDiscoveryError`, which classifies the higher-level discovery/
/// fetch/parse outcome `MTASTSPolicyManager` cares about).
public enum MTASTSHTTPFetchError: Error, Sendable, Equatable {
    /// `URLSession`'s response wasn't an `HTTPURLResponse` at all -- not
    /// expected for an `https://` URL in practice, handled defensively
    /// rather than force-cast.
    case notAnHTTPResponse
}

/// The production `MTASTSHTTPFetching` implementation: a plain `URLSession`
/// GET, default (fully-verified) TLS trust evaluation, no caching layer of
/// its own (`MTASTSPolicyManager` is the cache; asking `URLSession` to also
/// cache per HTTP semantics would just be a second, uncoordinated cache
/// with its own, RFC-9111-shaped expiry rules layered underneath the one
/// that actually matters here, RFC 8461 §3.2's `max_age`).
///
/// FIX #3 (MEDIUM security, milestone security review): **redirects are
/// never followed.** RFC 8461 §3.3 itself is explicit about this -- fetched
/// and verified directly against the published RFC text, not assumed:
/// "Policies fetched via HTTPS are only valid if the HTTP response code is
/// 200 (OK). HTTP 3xx redirects MUST NOT be followed". Before this fix,
/// `fetch(url:)` called `session.data(for:)` with no delegate at all, so
/// `URLSession`'s ordinary default behavior applied: HTTP(S) redirects
/// (including cross-host and cross-scheme, `https://` -> `http://`) were
/// followed automatically with nothing checking the redirect target. Since
/// the fetch domain is fully attacker-controlled the moment an attacker
/// controls a domain being emailed to, a malicious policy server could
/// redirect this fetch to an internal address or a plaintext-HTTP endpoint
/// -- a real request-forgery primitive, even though the fetched response is
/// only ever used for MTA-STS text parsing, never reflected back to anyone.
///
/// `RedirectRefusingTaskDelegate` below refuses **every** redirect
/// unconditionally (`completionHandler(nil)`) rather than attempting to
/// selectively allow same-host/HTTPS-only redirects -- RFC 8461 doesn't
/// require or expect redirect support for the well-known policy fetch at
/// all, so refusing entirely is both the RFC-mandated behavior and the
/// simplest safe choice. When a redirect is refused this way, the task
/// completes normally with the original 3xx response as its final result
/// (not an error) -- `MTASTSPolicyManager.fetchAndParsePolicy`'s existing
/// `guard response.statusCode == 200` already treats any non-200 status as
/// `MTASTSDiscoveryError.fetchFailed`, so a refused redirect is correctly
/// folded into the ordinary "fetch failed" path with no separate handling
/// needed here.
///
/// **Linux:** swift-corelibs-foundation ignores the per-task delegate
/// passed to `data(for:delegate:)`, and auto-follows redirects for any task
/// created with a completion handler, so the Darwin code path above
/// silently followed redirects there (seen with `swift:6.4-noble`: the
/// redirect test failed with "too many HTTP redirects"). On platforms that
/// use `FoundationNetworking`, each fetch therefore runs on its own
/// short-lived `URLSession` built from `session.configuration`, with
/// `RedirectRefusingFetchDelegate` as the *session* delegate driving a
/// delegate-based data task; only the injected session's configuration is
/// used there, not the session itself.
public struct URLSessionMTASTSFetcher: MTASTSHTTPFetching {
    private let session: URLSession

    /// - Parameter session: On Darwin, the session every fetch runs on. On
    ///   platforms that use `FoundationNetworking` (Linux), only its
    ///   `configuration` is used: each fetch runs on its own short-lived
    ///   session whose delegate refuses redirects, so a delegate set on
    ///   `session` (e.g. one handling authentication challenges) is not
    ///   consulted there.
    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func fetch(url: URL) async throws -> MTASTSHTTPResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        #if canImport(FoundationNetworking)
        let (data, response) = try await RedirectRefusingFetchDelegate.fetch(request, configuration: session.configuration)
        #else
        let (data, response) = try await session.data(for: request, delegate: RedirectRefusingTaskDelegate())
        #endif
        guard let http = response as? HTTPURLResponse else {
            throw MTASTSHTTPFetchError.notAnHTTPResponse
        }
        return MTASTSHTTPResponse(
            statusCode: http.statusCode,
            contentType: http.value(forHTTPHeaderField: "Content-Type"),
            body: Array(data)
        )
    }
}

/// FIX #3's mechanism: a per-request `URLSessionTaskDelegate` that refuses
/// every HTTP redirect unconditionally. `final class ... NSObject`
/// (`URLSessionTaskDelegate` requires an `NSObject`-conforming delegate on
/// both Darwin `Foundation` and `FoundationNetworking`), `@unchecked
/// Sendable`: holds no mutable state at all, so there is nothing for
/// concurrent task callbacks to race on.
private final class RedirectRefusingTaskDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // `nil` -- do not follow the redirect. The task completes with
        // `response` (the 3xx itself) as its final result.
        completionHandler(nil)
    }
}

#if canImport(FoundationNetworking)
/// The `FoundationNetworking` counterpart of `RedirectRefusingTaskDelegate`
/// (see `URLSessionMTASTSFetcher`'s "Linux" paragraph): the session delegate
/// of a one-fetch `URLSession`, so corelibs actually consults it for
/// redirects. It refuses every redirect, collects the body, and resumes the
/// caller's continuation when the task completes. `@unchecked Sendable`:
/// its mutable state is only touched under `lock`.
private final class RedirectRefusingFetchDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var body = Data()
    private var continuation: CheckedContinuation<(Data, URLResponse), any Error>?
    private var task: URLSessionDataTask?
    private var cancelled = false

    static func fetch(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> (Data, URLResponse) {
        let delegate = RedirectRefusingFetchDelegate()
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                delegate.start(session.dataTask(with: request), continuation: continuation)
            }
        } onCancel: {
            delegate.cancel()
        }
    }

    private func start(_ task: URLSessionDataTask, continuation: CheckedContinuation<(Data, URLResponse), any Error>) {
        lock.lock()
        let alreadyCancelled = cancelled
        if !alreadyCancelled {
            self.continuation = continuation
            self.task = task
        }
        lock.unlock()
        if alreadyCancelled {
            // Cancel the never-started task too: corelibs'
            // `finishTasksAndInvalidate()` waits for every task it created,
            // so an unstarted one would keep the session and this delegate
            // alive forever. `didCompleteWithError` then finds no
            // continuation and does nothing.
            task.cancel()
            continuation.resume(throwing: CancellationError())
        } else {
            task.resume()
        }
    }

    private func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        lock.unlock()
        // Completes through `didCompleteWithError` with `NSURLErrorCancelled`.
        task?.cancel()
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // `nil` -- do not follow the redirect. The task completes with
        // `response` (the 3xx itself) as its final result.
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        body.append(data)
        lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        self.task = nil
        let data = body
        lock.unlock()
        guard let continuation else { return }
        if let error {
            continuation.resume(throwing: error)
        } else if let response = task.response {
            continuation.resume(returning: (data, response))
        } else {
            continuation.resume(throwing: MTASTSHTTPFetchError.notAnHTTPResponse)
        }
    }
}
#endif

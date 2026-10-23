//
//  RetryBackoffPolicy.swift
//  PerfectSMTPCore
//
//  Pure data + a pure classification function, no NIO -- see plan §4.8.
//
//  Phase 1's `SMTPConnection.outcomeFor` (`Sources/PerfectSMTP/SMTPConnection.swift`)
//  originally hardcoded three backoff durations (900s/300s/120s) directly
//  into its own body, with a doc comment explicitly flagging them as
//  "placeholders populating `DeliveryResult`'s existing
//  `.queuedForRetry(nextAttempt:...)` shape correctly... even though
//  nothing in Phase 1 acts on it yet," deferring making them real to Phase
//  3. This type is that: a small, `Sendable`, transport-agnostic policy
//  carrying the same three durations (same default values, so every
//  existing Phase 1 call site's behavior is unchanged unless it opts in to
//  a different policy), plus the mechanical reply -> outcome classification
//  itself, factored out so both `SMTPConnection` (Phase 1, RCPT/DATA-phase
//  rejections) and `DirectMXRetryQueue` (Phase 3, MAIL-FROM-phase
//  rejections and every rescheduled retry) apply the *same* configured
//  policy rather than two independently-hardcoded copies of it.
//

import Foundation

/// The 421-vs-greylist-vs-other-4yz backoff policy (plan §4.8's corrected
/// distinction). Every `SMTPConnection` and `DirectMXRetryQueue` in this
/// package defaults to the exact same values Phase 1 originally hardcoded,
/// so adopting this type changes nothing for an existing caller who doesn't
/// explicitly configure a different policy.
public struct RetryBackoffPolicy: Sendable {
    /// Backoff after a `421` (RFC 5321 §3.8/§4.2.1: "service unavailable,
    /// closing the channel" -- typically overload/rate-limit). Deliberately
    /// longer than `greylist` -- retrying an overloaded receiver quickly is
    /// exactly the aggressive-reconnection behavior that makes the
    /// overload worse (plan §4.8's 421-vs-greylist correction).
    public var serviceUnavailable: TimeInterval
    /// Backoff after a first-contact greylist response (`450`/`451`/`452`)
    /// -- a normal, expected pattern from many receivers, not a failure
    /// signal.
    public var greylist: TimeInterval
    /// Backoff for any other `4yz` not covered above.
    public var defaultTransient: TimeInterval
    /// The longest single wait. Release review: delays now double with
    /// every attempt (`delay(for:attempt:)`), from the class's base delay
    /// above up to this cap, so a destination that stays down is retried
    /// across the retry queue's whole `maxAge` (5 days) rather than giving
    /// up after ten flat 5-minute waits. Default 4 hours.
    public var maximumBackoff: TimeInterval
    /// Each delay is randomly spread by up to this fraction either way
    /// (default 0.1, i.e. ±10%), so retries to one destination don't all
    /// land at once. 0 makes the schedule exact.
    public var jitter: Double

    public init(
        serviceUnavailable: TimeInterval = 900,
        greylist: TimeInterval = 300,
        defaultTransient: TimeInterval = 120,
        maximumBackoff: TimeInterval = 4 * 3600,
        jitter: Double = 0.1
    ) {
        self.serviceUnavailable = serviceUnavailable
        self.greylist = greylist
        self.defaultTransient = defaultTransient
        self.maximumBackoff = maximumBackoff
        self.jitter = min(max(0, jitter), 1)
    }

    /// The base delay for `reply`'s class: `serviceUnavailable` for 421,
    /// `greylist` for 450/451/452 (including the library's own synthesized
    /// 451 4.4.1 "no usable connection" and 4.7.5 MTA-STS replies),
    /// `defaultTransient` for any other 4yz.
    public func baseDelay(for reply: SMTPReply) -> TimeInterval {
        switch SMTPError.classify(reply) {
        case .serviceUnavailable: return serviceUnavailable
        case .greylisted: return greylist
        default: return defaultTransient
        }
    }

    /// The wait before retrying after `reply` on attempt number `attempt`
    /// (1 for the first send): `baseDelay × 2^(attempt-1)`, capped at
    /// `maximumBackoff`, then spread by `jitter`. With the defaults a
    /// greylist or connection failure waits about 5, 10, 20, 40 and 80
    /// minutes, then 2h40, then 4 hours each time. A real greylister lets
    /// the first retry through, so greylisting still sees the familiar
    /// 5-minute first retry.
    public func delay(for reply: SMTPReply, attempt: Int) -> TimeInterval {
        let base = baseDelay(for: reply)
        let exponent = Double(max(0, min(attempt - 1, 30)))
        let raw = min(maximumBackoff, base * pow(2, exponent))
        guard jitter > 0 else { return raw }
        return raw * Double.random(in: (1 - jitter)...(1 + jitter))
    }


    /// Mechanically classifies a reply into a `DeliveryResult.Outcome`,
    /// exactly like `SMTPError.classify(_:)` classifies it into a
    /// `SMTPError` case -- `.permanentlyFailed` for `5yz`,
    /// `.queuedForRetry` with this policy's matching backoff for anything
    /// else. Callers that have already classified a reply as a rejection
    /// (this codebase never calls this for a `2yz`/`3yz` reply) get a
    /// correctly-backed-off retry hint either way.
    public func classify(_ reply: SMTPReply, attempt: Int) -> DeliveryResult.Outcome {
        guard reply.replyClass != .permanentNegative else { return .permanentlyFailed(reply) }
        return .queuedForRetry(nextAttempt: Date().addingTimeInterval(delay(for: reply, attempt: attempt)), attempt: attempt, last: reply)
    }
}

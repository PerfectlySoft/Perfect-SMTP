//
//  SMTPError.swift
//  PerfectSMTPCore
//
//  Pure data model, no NIO — see plan §4.8. Retry-queue orchestration,
//  circuit breakers, and anything stateful are Phase 1/3; this file is
//  only the classification of a single `SMTPReply` into an error case.
//

public enum SMTPError: Error, Sendable {
    /// 4yz other than 421 — retry per backoff schedule.
    case transientFailure(SMTPReply)
    /// 421 specifically. RFC 5321 §3.8/§4.2.1: "service unavailable,
    /// closing the channel" — typically an overload/rate-limit signal.
    /// Handled distinctly from greylisting per plan §4.8's correction:
    /// treating it identically to 450/451/452 invites the exact
    /// aggressive-reconnection behavior that worsens the receiver's
    /// overload. (The actual "close the connection, use a longer
    /// backoff, feed the circuit breaker" behavior is Phase 1/3 — this
    /// type only carries the classification.)
    case serviceUnavailable(SMTPReply)
    /// 5yz — MUST NOT retry.
    case permanentFailure(SMTPReply)
    /// 450/451/452 first-contact — retry with delay.
    case greylisted(SMTPReply)
    case sizeExceeded(limit: Int)
    case authenticationFailed(SMTPReply)
    case starttlsRequired
    /// The CVE-2026-41319-class buffer-discipline violation: bytes read
    /// from the socket before the TLS handshake would otherwise be
    /// processed as post-TLS input.
    ///
    /// Milestone review finding (correctness): originally carried no
    /// associated value, so a legitimate TLS handshake failure (expired
    /// cert, cipher mismatch, network reset) during the fenced upgrade
    /// window was indistinguishable from an actual injection attack in
    /// logs/metrics. `underlying` carries the real cause when one exists
    /// (the separate-buffer path's NIOSSL handshake failure); `nil` when
    /// the violation was detected directly by this decoder's own
    /// residual-bytes logic (the same-buffer path), which has no
    /// diagnostic value beyond the fact `.starttlsInjection` itself
    /// already captures. Constrained `any Error & Sendable`, matching
    /// `.connectionFailed`'s existing precedent for carrying an opaque
    /// underlying error in a `Sendable` enum.
    case starttlsInjection(underlying: (any Error & Sendable)?)
    /// The server's TLS certificate didn't verify: an untrusted or expired
    /// chain, a name that doesn't match the host, or (for MTA-STS) no DNS
    /// subjectAltName for the MX host. Reported separately from
    /// `.starttlsInjection`, which now only means bytes were injected
    /// around the upgrade.
    case tlsCertificateInvalid(underlying: (any Error & Sendable)?)
    /// MTA-STS / DANE policy violation (Phase 4).
    case tlsPolicyViolation(String)
    case circuitOpen
    case connectionFailed(any Error & Sendable)
    /// Failure AFTER 354/DATA, BEFORE 250 — the point of no return. Never
    /// auto-retried; see `DeliveryResult.Outcome.ambiguous`.
    case ambiguousDelivery(SMTPReply?)

    /// Mechanically classifies a reply into the matching error case, using
    /// only `replyClass` and (for the 4yz case) the exact code — never
    /// guessed. This is the 421-vs-greylist correction from plan §4.8:
    /// `421` classifies separately from `450`/`451`/`452`. Only meaningful
    /// for 4yz/5yz replies; 2yz/3yz/unknown replies are not failures and
    /// fall back to `.transientFailure` as a defensive default (callers
    /// should not invoke this for a reply they haven't already identified
    /// as a failure).
    public static func classify(_ reply: SMTPReply) -> SMTPError {
        switch reply.replyClass {
        case .permanentNegative:
            return .permanentFailure(reply)
        case .transientNegative:
            switch reply.code {
            case 421:
                return .serviceUnavailable(reply)
            case 450, 451, 452:
                return .greylisted(reply)
            default:
                return .transientFailure(reply)
            }
        case .positiveCompletion, .positiveIntermediate, .unknown:
            return .transientFailure(reply)
        }
    }
}

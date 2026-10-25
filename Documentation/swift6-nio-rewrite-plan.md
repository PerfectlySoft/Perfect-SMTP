# Perfect-SMTP Swift 6.2 / SwiftNIO Rewrite — Plan

Date: 2026-07-18
Status: **Implemented; shipped in 6.0.0. Kept as design history.** Source comments cite this plan's sections ("plan §4.3") for the reasoning behind a choice, so it stays here unedited. Several review passes changed the final API after it was written: for how the shipped code actually behaves, read [the user guide](user-guide.md) and the README, not this plan. Original status, as written: *Planned, reviewed, not yet implemented.* This document is the actionable output of a design → architecture → parallel expert review cycle (application architect, Swift-concurrency expert, SMTP-protocol/adversarial reviewer). No code has been written yet. All work described here happens on feature branches, never directly on `master`.

## 1. Why this library needs a full rewrite, not a modernization pass

The current `Perfect-SMTP` (`Sources/PerfectSMTP/PerfectSMTP.swift`, ~400 lines, dated 2016) does not implement SMTP at all. It hand-builds a MIME message string and hands the whole thing to `libcurl` via `PerfectCURL`'s `CURLRequest` (`.mailFrom`/`.mailRcpt`/`.upload`/`.userPwd` options) — libcurl's blocking, built-in SMTP client does the actual protocol conversation. There is no STARTTLS sequencing of its own, no AUTH mechanism control, no connection pooling, no retry logic, no DKIM signing, and `send()` is a single synchronous, blocking, throwing call.

Two real correctness bugs were found by direct inspection of the current code and are fixed structurally (not patched) in this rewrite:

1. **Bcc header leak** (`makeBody()`, line ~313): Bcc addresses are correctly placed in the SMTP envelope (`RCPT TO`) but a `Bcc:` **header** is also written into the message body sent to every recipient — defeating the entire purpose of Bcc.
2. **Fake quoted-printable subject encoding** (`makeBody()`, line ~331): a fallback path emits `Subject: =?utf-8?Q?<raw unescaped subject>?=` — labeled quoted-printable but never actually QP-encoded. Corrupts any subject containing non-ASCII or special characters that hits this branch.

Given the scope of what's missing (§7) and the two structural bugs, patching the existing file is not viable — this is a ground-up rewrite using this ecosystem's established resurrection conventions.

## 2. Dependency audit — no other Perfect library needs updating

The current `Package.swift` depends on three GitHub packages. Checked against the local resurrection set at `/Users/timtaplin/Perfect-Resurrection/`:

| Dependency | Local resurrection status | Disposition |
|---|---|---|
| `Perfect-CURL` | Present, already resurrected | **Dropped.** Per this ecosystem's own established direction (Perfect-FileMaker already migrated off it — task history: "drop PerfectCURL, convert to async/await URLSession"), and because libcurl's SMTP path is internally synchronous, wrapping it can't deliver the "fully concurrent" requirement without repeating the exact blocking-bridge pattern (`AsyncBridge`) this project's own Perfect-Lasso history already identified as a real bug source. |
| `Perfect-Crypto` | **Absent from the local set** | **Not resurrected.** Used only for base64 encoding — trivially replaced by `Foundation.Data.base64EncodedString()` and, for DKIM, `apple/swift-crypto` (the same official package Perfect-Notifications already depends on for its APNs JWT signing). |
| `Perfect-MIME` | **Absent from the local set** | **Not resurrected.** Used only for a MIME-type-by-file-extension lookup table — replaced by a small hand-rolled table in `PerfectSMTPCore`. |

**Conclusion: no other Perfect-Resurrection library requires new work as a consequence of this rewrite.** The two genuinely-missing upstream dependencies (Perfect-Crypto, Perfect-MIME) are deliberately *not* resurrected — every other library in this ecosystem was either modernized in place as a first-party fork, or had a legacy dependency dropped in favor of an *official* Apple/SSWG package (never a competing third party's implementation of the same thing), and Perfect-SMTP follows that same pattern rather than growing the resurrection set to cover two libraries whose entire purpose here is satisfied by `Foundation` + `swift-crypto`.

New dependencies are `swift-nio`, `swift-nio-ssl`, `swift-crypto` — all official, and all already used elsewhere in this exact ecosystem (Perfect-NIO for the first two, Perfect-Notifications for the third).

## 3. Transport-implementation options considered

Explicitly requested review before committing to an approach. Live-checked, not assumed:

- **Adopt/fork a third-party Swift SMTP library.** `SwiftMail` (BSD-2, actor-based async/await, XOAUTH2) is disqualified outright — **no Linux support**, breaking this ecosystem's Linux CI commitment. `sersoft-gmbh/swift-smtp` (Apache-2.0, genuinely NIO-based, actively maintained) covers only configured-host submission; none of DKIM, direct-MX delivery, connection pooling with circuit-breaking, or MTA-STS/DANE exist in it or any other candidate checked. No third party covers more than a fraction of the required scope, and adopting one would deviate from how every other library in this ecosystem was resurrected (first-party fork, or drop-for-an-official-package — never adopt a competing third party's implementation of the core thing being resurrected).
- **Keep wrapping libcurl, make it async.** Contradicts "swift native, fully concurrent" directly (libcurl's mail path is internally synchronous); Perfect-FileMaker already moved off Perfect-CURL in this ecosystem for the same reason; gives no control over DKIM/pooling/MX-delivery/TLS policy.
- **Apple's `Network.framework`.** Rejected immediately — Apple-only, breaks Linux support maintained everywhere else in this ecosystem.
- **Hand-roll the SMTP wire protocol on `swift-nio` + `swift-nio-ssl`.** Matches Perfect-NIO's own established pattern in this exact ecosystem. Full control over the STARTTLS security invariant, connection pooling, pipelining, and DKIM signing pipeline ordering. **Chosen approach**, behind a pluggable `Transport` abstraction (§4.2).

**Delegating to an already-operated MTA — elevated to a top-level, co-equal delivery strategy, not a fallback.** Many real deployments already run a hardened MTA (Postfix, Exim, a corporate relay) as a separate, already-configured service — for those users, handing a fully-composed message to that existing infrastructure is often the *preferred* choice, not a consolation prize for skipping DKIM/direct-MX. This plan treats "let something else handle real delivery" as two concrete, both-first-class mechanisms rather than one deprioritized escape hatch:
- **Network handoff, "elsewhere"** — plain SMTP submission to a self-hosted or internal MTA. This is `RelayTransport` (§4.2), whose scope explicitly includes not just commercial ESPs (SendGrid/Postmark/SES) but any already-configured SMTP relay reachable over the network, including an internal host on a trusted network with no AUTH at all. No separate transport implementation is needed for this case — it's the same NIO-based SMTP client, just pointed at a destination the operator already trusts.
- **Local handoff, "in the local system"** — `LocalMTATransport`, an async-safe wrapper around the `sendmail`/`postfix -t` command-line interface (the same pattern PHP's `mail()` and countless other language runtimes use). Moved up from a late, low-priority phase to ship in **Phase 1** alongside `RelayTransport` (§9) — for a user who already runs Postfix locally, this is arguably the simplest and lowest-risk path to "Perfect-SMTP composes correct, DKIM-signable messages; the local MTA does everything else," and there's no reason to make that user wait for the harder direct-MX phases.

The hardest piece — Perfect-SMTP being the terminal MTA itself, doing its own MX resolution and delivery (`DirectMXTransport`) — remains a distinct, later phase for users who genuinely want that (§9, Phase 3), not a prerequisite for a usable first release.

## 4. Target architecture

### 4.1 Package / module layout

Two targets, two library products, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`, `.swiftLanguageMode(.v6)` on every target (matching Perfect-NIO's current baseline, not Perfect-Notifications' older `6.0`/`.v13` one):

```
PerfectSMTPCore   // Foundation + Crypto + _CryptoExtras only. NO NIO IMPORT.
                  // Value types, MIME builder, RFC 2047 header encoder, dot-stuffing,
                  // SASL byte-framing, DKIM signer, reply/error/result model.
PerfectSMTP       // + swift-nio, swift-nio-ssl, swift-log.
                  // Channel handlers, protocol state machine, connection-pool actor,
                  // Transport strategies, SMTPMailer public API.
                  // @_exported import PerfectSMTPCore
```

**Perfect-SMTP has zero knowledge of Lasso — no third target, no Lasso-shaped types, no dash-param anywhere in this package.** This corrects the original draft of this plan, which had sketched a `PerfectSMTPLasso` target living inside this repo. That's inconsistent with how every other consumed-by-Lasso library in this ecosystem is actually structured: `PerfectFileMakerLassoExecutor` and `PerfectCRUDLassoExecutor` don't live in Perfect-FileMaker or Perfect-CRUD — they live entirely inside `/Users/timtaplin/Perfect-Lasso/Sources/LassoPerfectFileMaker/` and `.../LassoPerfectCRUD/`, as targets in the *Perfect-Lasso* repo that take a plain dependency on the resurrected library. Perfect-FileMaker itself has zero Lasso imports (confirmed by inspection — one doc-comment mentions a consumer's tool name for context, nothing more). Perfect-SMTP follows the identical pattern: it is a general-purpose, domain-agnostic SMTP library with a plain Swift-native API; a Lasso-compatibility adapter, if and when one is wanted, is a **separate, future task that belongs entirely in the Perfect-Lasso repository** (analogous to `LassoPerfectFileMaker`), consuming this library's public API exactly as any other Swift caller would. §6 below is kept as reference research for that future task, but is explicitly not part of this package or this plan's deliverable — see the note at the top of §6.

The `PerfectSMTPCore` / no-NIO-import boundary is a deliberate compile-time enforcement of "MIME composition and DKIM signing are transport-agnostic and must not be able to reach into a live channel or re-encode after signing" — a build error, not a code-review hope.

**Dependencies, each justified:** `swift-nio` 2.65+ (channels/event loops/`ByteBuffer`), `swift-nio-ssl` 2.27+ (`NIOSSLClientHandler` for implicit TLS and the STARTTLS upgrade), `swift-crypto` 3.0+ (`Crypto` for SHA-256/Ed25519 DKIM signing, `_CryptoExtras` for RSA-SHA256 DKIM signing — see §4.6), `swift-log` 1.5+ (structured logging of the SMTP conversation, essential for deliverability debugging).

**Deliberately excluded:** `swift-nio-extras` — SMTP's multiline-reply parsing and PIPELINING batching both need a custom codec regardless, so its `LineBasedFrameDecoder`/`RequestResponseHandler` don't fit cleanly; add it later only if its quiescing helpers become useful. No DNS resolver library — none exists as an official SSWG package; the Phase 3 direct-MX resolver is hand-rolled over NIO UDP, which is itself the single largest engineering item in this whole plan (§9, Phase 3).

**CI tier:** Tier A (pure-Swift, full `swift test` on Linux, matrix entry in `.github/workflows/linux.yml`) — this library declares no `systemLibrary` of its own (swift-nio-ssl vendors BoringSSL internally). Add a `SMTP_TESTS=1`-gated service-container job (MailHog or smtp4dev) mirroring the existing `redis` job's pattern, for the live-integration test tier (§5).

### 4.2 The `Transport` abstraction

```swift
public protocol SMTPTransport: Sendable {
    /// The message bytes are transmitted verbatim (modulo wire-level dot-stuffing,
    /// which is signature-preserving — see §4.6). A transport MUST NOT add,
    /// reorder, or re-encode headers or body.
    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult]
}

public struct SignedMessage: Sendable {
    public let rfc5322: [UInt8]      // headers + CRLFCRLF + body, DKIM-Signature already prepended
    public let estimatedSize: Int
}
```

Three conforming strategies, all `Sendable`. Per §3, delegating to an already-operated MTA (`RelayTransport` and `LocalMTATransport`) is a top-level, first-class delivery strategy, not a fallback — both ship in Phase 1, alongside each other:

- **`RelayTransport`** (Phase 1) — owns a `SMTPConnectionPool` keyed to one configured SMTP host. Scope explicitly includes both commercial ESPs (SendGrid/Postmark/SES, with AUTH) and self-hosted/internal MTAs reachable over the network (a corporate Postfix/Exim relay, possibly with no AUTH on a trusted network) — the same NIO-based client either way.
- **`LocalMTATransport`** (Phase 1) — async-safe wrapper around the local `sendmail`/`postfix -t` command-line interface, for operators who already run an MTA on the same host. Composes a correct, DKIM-signable message and hands it off; delivery, retries, and TLS policy from that point on are the local MTA's responsibility, not this library's.
- **`DirectMXTransport`** (Phase 3) — MX resolution, per-destination delivery, retry queue, greylisting, circuit-breaking, multi-host pool. For operators who want Perfect-SMTP itself to be the terminal MTA. The hardest, most novel piece — a later, distinct phase, not a prerequisite for a usable first release.

`SMTPMailer` is generic over `any SMTPTransport`; the DKIM signer, MIME composer, and message model are written once and shared by all three.

### 4.3 SMTP protocol state machine on NIO

**Revised after direct comparison against this ecosystem's own precedent.** Perfect-NIO — already resurrected, in this same set of repos — drives its WebSocket and HTTP/1.1 conversations via `NIOAsyncChannel`'s `NIOAsyncChannelInboundStream.AsyncIterator` + `NIOAsyncChannelOutboundWriter`, a plain `for try await` loop; `EventLoopFuture` appears in that codebase only at the narrow HTTP-upgrade-negotiation boundary, bridged immediately, never as a general request/reply correlation mechanism. The original draft of this section leaned on a hand-rolled `EventLoopPromise`-per-command correlation queue for the *entire* conversation, which is less aligned with that precedent than it should be, and — per the concurrency review (§10) — was also the source of the design's one critical data race. Corrected design below eliminates that queue for the bulk conversation rather than just fixing its synchronization.

**Two-phase channel lifecycle:**

**Phase A — bootstrap (explicit, low-level, tightly scoped).** Connection establishment, optional implicit TLS (port 465), EHLO, and — for STARTTLS — the negotiate-and-upgrade dance, are driven by a minimal explicit `ChannelDuplexHandler` (`SMTPBootstrapHandler`) sitting above a custom `SMTPResponseDecoder` (`ByteToMessageDecoder`). This phase is kept intentionally small and low-level because the STARTTLS security invariant (below) genuinely needs byte-precise control over the inbound cumulation buffer at the exact moment of upgrade, and mid-stream pipeline reconfiguration (remove the plaintext decoder, insert `NIOSSLClientHandler`, add a fresh decoder) is more ergonomic with an explicit handler than with an already-running `NIOAsyncChannel`, which doesn't want its pipeline mutated out from under an in-progress inbound iteration. `SMTPBootstrapHandler` uses at most a single outstanding `EventLoopPromise<SMTPReply>` at a time (write one command, await its one reply) — never a queue, since bootstrap commands are never pipelined.

**Phase B — the bulk conversation (native async/await, no hand-rolled correlation at all).** Once bootstrap completes (implicit TLS connected, or STARTTLS negotiated and the pipeline swapped), the now-ready `Channel` is wrapped via `NIOAsyncChannel(wrappingChannelSynchronously:)` into `NIOAsyncChannel<SMTPReply, SMTPCommand>` — confirmed to be the correct, documented API for exactly this "I already have a live `Channel`, hand it to the async bridge now" case (must be called on the channel's own event loop, before any other pipeline event, matching `NIOAsyncChannel`'s documented requirement). Everything from the post-TLS EHLO onward — capability re-negotiation, AUTH's SASL exchange (including the `async` `XOAuth2.tokenProvider()` refresh callback), MAIL/RCPT/DATA, PIPELINING — is driven by the connection actor as a plain `for try await reply in inboundStream` loop paired with `try await outboundWriter.write(command)`. **This removes the correlation queue, and the data race that came with it, by construction rather than by careful synchronization:** SMTP replies are guaranteed to arrive in the same order commands were issued (RFC 2920 §3, including under PIPELINING), so "write N commands, then read N replies off the iterator in order" needs no shared correlation structure at all — the actor's own task is the only reader and the only writer, sequentially, within one `async` function. The `XOAuth2` token refresh is trivially safe here too: `await tokenProvider()` just suspends the actor's task between one `outboundWriter.write` and the next; there is no promise anyone else is waiting on, and no event-loop code involved at all.

**Reply decoding:** `SMTPResponseDecoder` accumulates lines until a terminal (non-`-`-continued) line, emits one `SMTPReply { code, enhancedStatus?, lines }`, and exposes whether residual bytes remain in its buffer after emitting a reply — used by both phases, but the residual-bytes check specifically only matters during Phase A's STARTTLS sequence (below).

**Capability negotiation:** parsed from the EHLO multiline reply into a `Capabilities` struct (`startTLS`, `authMechanisms`, `size`, `eightBitMIME`, `smtpUTF8`, `pipelining`, `chunking`, `dsn`, `enhancedStatusCodes`). Nothing downstream ever assumes a capability not present in this struct.

**PIPELINING (Phase B):** when advertised, the actor writes `MAIL FROM` + all `RCPT TO` + `DATA` via the outbound writer without awaiting between them, then reads the corresponding replies off the inbound iterator in order — degrades to lock-step (await each reply before the next write) when the capability is absent, same loop either way, just with or without the intervening awaits. **Corrected semantics (protocol review):** if a `RCPT TO` in the middle of a pipelined batch returns a rejection (e.g. `550`), the remaining pipelined `RCPT` replies are still consumed in order off the iterator; `DATA` proceeds only if at least one `RCPT` was accepted (otherwise the pipelined `DATA` itself draws `503`/`554` and the message body must never be sent); per-recipient `DeliveryResult`s reflect the actual mixed outcome. This must be an explicit, tested behavior (§5), not an incidental consequence of the loop's plumbing.

**Mid-conversation disconnect (Phase B):** `NIOAsyncChannel`'s inbound `AsyncSequence` terminates (throws or ends) when the channel closes, so an actor mid-`for try await` loop observes the disconnect directly through normal Swift error propagation — there is no separate "fail every outstanding promise" step to remember, because there is no promise queue left to fail. This is a direct consequence of removing the queue, not a new mechanism bolted on to replace it. A required automated test (§5) still confirms this propagates correctly rather than hanging.

**STARTTLS upgrade — the security invariant, corrected and made testable (Phase A only).** Stated precisely: *no byte read from the socket before the TLS handshake may be processed as post-TLS input.* This defends against a real, current CVE class: CVE-2026-41319 in MailKit (April 2026 — pre-TLS buffered bytes survived into the post-handshake pipeline and forced a SASL mechanism downgrade), same lineage as Postfix CVE-2011-0411, Thunderbird CVE-2021-23993, Dovecot CVE-2021-33515.

Corrected sequence, entirely within `SMTPBootstrapHandler` (two gaps closed from the original 6-step sketch, per the protocol review):

1. Write `STARTTLS`, await the reply.
2. **Immediately upon writing `STARTTLS`, set `autoRead = false`** on the channel (fencing further reads) — this closes the TOCTOU gap the original sequence had: the event loop is otherwise free to service another `channelRead` between the residual-bytes assertion below and the actual decoder swap, and the assertion alone is a point-in-time check, not a barrier.
3. On `220`: assert `SMTPResponseDecoder.hasResidualBytes == false`. If any bytes remain beyond the `220 Ready\r\n` line, throw `SMTPError.starttlsInjection`, close the channel, do not upgrade.
4. `context.pipeline.syncOperations.removeHandler(decoder)` — discard the plaintext decoder. **The decoder's `decodeLast` override must explicitly treat any leftover buffered bytes as `.starttlsInjection`, not forward them** — `ByteToMessageDecoder` removal triggers `decodeLast`, which is designed to flush remaining bytes by default, the opposite of "discard entirely," and the original design didn't address this.
5. Add `NIOSSLClientHandler` at `.first`.
6. Add a **fresh** `SMTPResponseDecoder` above it, then re-enable `autoRead`.
7. On handshake-complete: reset `capabilities` to empty, re-issue EHLO — this is the first command sent once Phase B's `NIOAsyncChannel` wrapping is complete, so the post-TLS capability re-negotiation naturally happens in the async-native loop, and only the post-TLS capability list is ever used for AUTH mechanism selection.

Automated regression test (§5) must feed the injected bytes in a **second, separate** inbound read/buffer (not concatenated into the same buffer as the `220`), since a single-buffer test only exercises the simpler case.

### 4.4 Connection pool

```swift
actor SMTPConnectionPool {
    struct Key: Hashable, Sendable { let host: String; let port: Int; let tls: TLSMode }
    private var idle: [Key: [PooledConnection]] = [:]
    private var activeCount: [Key: Int] = [:]
    private var totalActive = 0
    private var breaker: [Key: CircuitBreakerState] = [:]   // co-located, see below
    private let maxPerHost: Int
    private let maxTotal: Int
    private let idleTimeout: Duration

    func withConnection<R: Sendable>(to key: Key, _ body: (SMTPConnection) async throws -> R) async throws -> R
    func shutdown() async   // required — see below
}
```

Per-destination keying by `(host, port, tls)`. Bounded concurrency enforced inside the actor (no locks — the actor is the mutual-exclusion mechanism).

**Reentrancy discipline — corrected (concurrency review finding, medium, required).** The capacity check and its corresponding reservation (`activeCount` increment, or popping a connection from `idle`) must happen **synchronously in the same actor activation, before the first `await`** in `withConnection`. Concrete failure this closes: with `maxPerHost = 1`, Task A checks `activeCount == 0`, then `await`s dialing (suspends); Task B reenters the actor during A's dial, reads the still-unincremented `activeCount == 0`, also passes the check and dials — both later increment, `activeCount == 2`, the cap is silently violated. Reserving the slot before any suspension point closes this check-then-act race.

**Cancellation and teardown — required, previously unspecified (concurrency review finding, high).** A waiter parked on the pool's internal suspension queue whose `Task` is cancelled must have its continuation resumed with `CancellationError` and removed from the waiter list — implemented via `withTaskCancellationHandler` whose `onCancel` hops back onto the actor to perform the removal. Because a cancellation and a concurrent `release()` can both target the same waiter, there must be a single-owner guard (whichever removes the waiter id first wins; the other no-ops) to prevent a double-resume crash. Separately, the pool needs an explicit `shutdown()` that drains any still-parked waiters, resuming each with an error — actors have no automatic mechanism to wake suspended continuations on deinit, so without this, waiters present at shutdown hang forever. When `release()` wakes a waiter, slot ownership (`activeCount` increment) must transfer atomically as part of the same actor activation that resumes it, so a freshly-arriving checkout can't race in and steal the just-freed slot.

**Idle eviction:** timestamp-based; checkout also validates liveness and re-dials a dead socket (servers silently drop idle connections).

**Circuit breaker — co-located, not a separate actor (concurrency review recommendation, adopted).** Breaker state lives inside the pool actor, keyed alongside `activeCount`/`idle`, rather than in a separately injected actor. A separate breaker actor would add a cross-actor hop and an extra suspension point on every checkout, widening the pool's own reentrancy window and creating a TOCTOU seam between "breaker said `.halfOpen`" and the pool acting on it; co-location lets "check breaker + reserve slot" happen in one uninterrupted actor activation. Only revisit this if breaker state genuinely needs to be shared across multiple pool instances.

**Connections never cross tasks.** Callers submit work through the `withConnection` closure; `SMTPConnection` wraps a NIO `Channel` (itself `Sendable` and thread-safe) and exposes only `async` methods that hop to the channel's event loop via `writeAndFlush`/`EventLoopFuture.get()` — no `@escaping`-across-isolation machinery needed, since the payloads crossing are `Sendable` value commands.

### 4.5 AUTH abstraction

```swift
public protocol SASLMechanism: Sendable {
    var name: String { get }
    mutating func initialResponse() async throws -> [UInt8]?
    mutating func respond(to challenge: [UInt8]) async throws -> [UInt8]
    var isComplete: Bool { get }
}
```

`SASLPlain`/`SASLLogin` (the workhorses — SendGrid/Postmark/SES issue API keys as SMTP passwords), and **first-class `XOAuth2`**:

```swift
public struct XOAuth2: SASLMechanism {
    public let username: String
    public let tokenProvider: @Sendable () async throws -> String   // refresh callback
}
```

XOAUTH2/OAUTHBEARER (RFC 7628) framing: `user=<username>\x01auth=Bearer <token>\x01\x01`, base64-encoded. **This is mandatory, not optional**, in 2026: Google Workspace disabled legacy SMTP password auth as of March 14 2025; Microsoft 365's Basic-auth SMTP is being disabled by default for existing tenants end of 2026 and removed entirely by 2H2027. The library formats the framing and calls the caller-supplied `tokenProvider` — it does not itself run an OAuth2 authorization flow. On a `535`/re-challenge, `tokenProvider()` is called again and the exchange retried once before surfacing `SMTPError.authenticationFailed`. Mechanism selection uses **only** the post-TLS EHLO `AUTH=` list, defeating mechanism-downgrade attacks. `SASLCramMD5`/`SASLScramSHA256` are deferred (§10, out of initial scope) — every major relay provider is covered by PLAIN/XOAUTH2, and SCRAM's PBKDF2 dependency needs its cross-platform swift-crypto availability confirmed before committing to it.

### 4.6 DKIM signer

```swift
public struct DKIMSigner: Sendable {
    public enum Algorithm: Sendable { case rsaSHA256, ed25519SHA256 }
    let domain: String; let selector: String; let signedHeaders: [String]
    let canon: (header: Mode, body: Mode)   // default relaxed/relaxed
    let keys: [SigningKey]                  // one → single-sign; two → dual RSA+Ed25519

    public func sign(_ message: RFC5322Message) throws -> RFC5322Message
}
```

**Placement — the ordering invariant.** Signing is the last transformation in `PerfectSMTPCore` before the message is frozen into `SignedMessage`; nothing downstream re-encodes. **Confirmed correct by the protocol review:** wire-level dot-stuffing (applied by the transport's DATA writer, after signing) is signature-preserving, because DKIM canonicalization operates on the logical message and dot-stuffing is a wire-transparency mechanism the receiver reverses before verification — these are genuinely orthogonal, not a hazard.

**swift-crypto integration, confirmed:** SHA-256 + Ed25519 (RFC 8463) via the core `Crypto` module; RSA-SHA256 (RFC 6376's mandated algorithm) via `_CryptoExtras._RSA.Signing.PrivateKey`, PEM/DER import, padding mode `.insecurePKCS1v1_5` — despite the alarming-sounding name, **this is exactly the correct RFC 6376-mandated PKCS#1 v1.5 padding, not a compromise** (confirmed by the protocol review). Minimum RSA-2048 keys enforced at construction. `_CryptoExtras` is an underscore-prefixed, semi-stable SPI module — pin the swift-crypto version. Dual RSA+Ed25519 signing emits two `DKIM-Signature` headers (RSA required for broad receiver compatibility in 2026; Ed25519 additive, adoption still partial).

**Sendability caveat (concurrency review, verify before implementation):** `Curve25519.Signing.PrivateKey` is confirmed `Sendable`. **`_RSA.Signing.PrivateKey`'s `Sendable` conformance in the pinned swift-crypto version must be verified before committing `DKIMSigner` to a plain `Sendable struct`** — if it isn't, the fallback must not be `@unchecked Sendable` (this ecosystem's own conventions explicitly reject that as a race-silencer, not a fix); the correct fallback would be wrapping key material behind an actor or a genuinely-`Sendable` box type.

**Oversigning — corrected (protocol review finding, required).** "List security-relevant headers more times in `h=` than they occur" must specifically include headers that are **currently absent** from the message: the RFC 6376 §5.4/§8.15 semantics are "count+1," including a count of zero — i.e., a header with zero real occurrences still gets exactly one `h=` entry, so that if an attacker later injects that header (e.g. adds a `Bcc:` or a second `From:`), its presence breaks the signature. Naively only oversigning headers already present silently fails to protect against exactly the class of injection oversigning exists to prevent. Concretely, the always-oversigned set should include (at minimum): `From` (count+1 — RFC 6376 mandates `From` be signed at all), `Subject`, `To`, `Cc`, `Date`, `Reply-To`, `Sender`, `Content-Type`, `MIME-Version` — each present once → oversign to two; each absent → oversign to one. Verify the implementation against RFC 6376 Appendix A test vectors (both RSA and Ed25519/RFC 8463 vectors) as a required unit test (§5).

**Alignment lint:** `signedHeaders`' `d=` domain should relaxed-align with the `From:` header domain for DMARC to pass; the mailer emits a `Logging` warning when they diverge (never a hard error — misalignment is sometimes intentional, e.g. third-party sending infrastructure).

### 4.7 Message / MIME model

All `Sendable` value types in `PerfectSMTPCore`:

```swift
public struct EmailAddress: Sendable, Hashable {
    public var displayName: String?
    public var address: String        // addr-spec, always stored separately from display name
}

public struct EmailMessage: Sendable {
    public var from: EmailAddress
    public var sender: EmailAddress?              // distinct Sender: header (Lasso -sender)
    public var replyTo: [EmailAddress]
    public var to, cc: [EmailAddress]
    // NOTE: no `bcc` field here at all — see the corrected Bcc fix below.
    public var subject: String
    public var textBody: String?
    public var htmlBody: String?
    public var inlineImages: [InlineResource]      // multipart/related, cid: (Lasso -htmlImages)
    public var attachments: [Attachment]           // Sendable payloads only — see caveat below
    public var priority: Priority = .normal
    public var date: Date?                         // auto-synthesized when nil — see §7
    public var messageID: String?                  // auto-synthesized when nil, domain-scoped to DKIM d=/envelope-from
    public var inReplyTo: String?
    public var references: [String]
    public var listUnsubscribe: ListUnsubscribe?    // RFC 8058 (Phase 5)
    public var autoSubmitted: AutoSubmitted?        // RFC 3834 (Phase 5)
    public var precedence: Precedence?              // de facto, RFC 3834-adjacent (Phase 5)
    public var extraHeaders: [(name: String, value: String)]   // denylist-filtered — see below
    public var charset: String = "utf-8"
    public var defaultDisposition: ContentDisposition = .attachment
}

public struct SMTPEnvelope: Sendable {
    public var mailFrom: ReversePath          // see the corrected null-return-path handling below
    public var recipients: [String]           // to + cc + BCC addr-specs — the ONLY place Bcc lives
    public var size: Int?
    public var dsn: DSNRequest?
}

public enum ReversePath: Sendable {
    case address(String)   // MAIL FROM:<address>
    case null               // MAIL FROM:<> — required for DSNs/bounces/auto-replies, RFC 5321 §4.5.5
}
```

**Bug #1 fix (Bcc leak) — corrected to be genuinely structural (protocol review finding, required).** The original design's fix ("envelope/header separation makes the leak architecturally impossible") was directionally right but incomplete as specified: it never stated that `EmailMessage` itself carries no `bcc` field, and never addressed `extraHeaders` as a reintroduction vector. Corrected: **`EmailMessage` has no `bcc` field at all** — Bcc addresses are supplied directly as extra entries in `SMTPEnvelope.recipients` by the caller (the `bcc:` parameter on `SMTPMailer.send`, §4.9), never as part of the composed message. `MIMEComposer` therefore has no `bcc` data to accidentally serialize. Separately, `extraHeaders` is run through an explicit denylist at composition time that strips/rejects `Bcc`, `To`, `Cc`, `From`, `Return-Path`, and other envelope/routing-critical header names — closing the reintroduction path where any caller could otherwise smuggle a `Bcc:` header back in via `extraHeaders`. Required test: assert a Bcc address supplied via `send(bcc:)` ends up in `SMTPEnvelope.recipients` and that no `Bcc:` header appears in the serialized message under any code path, including via `extraHeaders`.

**Bug #2 fix (fake QP subject) — corrected to be RFC-conformant, not just "not obviously broken" (protocol review finding, required).** A `HeaderEncoder` implements real RFC 2047 encoded-words with two corrections the original sketch missed: (a) folding at the 75-char-per-encoded-word limit must happen on **character boundaries**, never splitting a multi-byte UTF-8 sequence across two encoded-words (a byte-oriented fold produces mojibake on decode); (b) encoded-words must **never** be emitted inside a `quoted-string` (RFC 2047 §5 forbids it — a receiver that sees `"=?utf-8?B?…?="` treats it as literal text, not as something to decode). Non-ASCII display-name phrases are emitted as bare encoded-words; ASCII-but-special-character phrases (e.g. containing a comma) use ordinary RFC 5322 `quoted-string`, never both mechanisms on the same phrase. Required tests: a long non-ASCII subject that must fold across multiple encoded-words without corrupting a multi-byte character at the boundary; a display name mixing quotes and non-ASCII content.

**Null return-path for bounces — added (protocol review finding, required, previously entirely absent from the design).** RFC 5321 §4.5.5 requires DSNs, auto-replies, and any bounce-class message to use an empty reverse-path (`MAIL FROM:<>`) to prevent mail loops. `SMTPEnvelope.mailFrom` is modeled as the `ReversePath` enum above specifically so this is representable and the serializer can emit exactly `MAIL FROM:<>` for the `.null` case — a plain `String` (as originally sketched) can neither represent nor guarantee this. **Scope decision:** Phase 1-3 of this library never generates its own DSNs/NDRs — permanent failures are reported to the caller as `.permanentlyFailed` results, and it is the caller's responsibility to decide whether/how to bounce. If a future phase adds NDR generation, it MUST use `.null` unconditionally for the generated bounce's own envelope. Required test: `.null` serializes to exactly `MAIL FROM:<>`.

**Attachment Sendability caveat (concurrency review, design constraint to enforce going forward):** `Attachment`/`InlineResource` payloads must stay value types (`Data`/`[UInt8]` or a `Sendable` file-reference token) — never an `InputStream`/`FileHandle`/streaming reference type, which would silently break the whole value-type-crosses-task-boundaries story this design depends on.

**Charset/encoding default (a documented new guarantee — neither Lasso 8.5 nor Lasso 9 specifies a default for `-characterSet`/`-transferEncoding`, confirmed by the Lasso research in §6):** UTF-8 for all text; quoted-printable transfer-encoding for non-ASCII `text/plain`/`text/html` parts, `7bit` for pure-ASCII parts, base64 for attachments/inline images. Chosen for safety and determinism (QP survives non-8BITMIME hops; base64 attachments need no capability negotiation) over opportunistically using raw 8-bit when 8BITMIME/SMTPUTF8 are advertised — the marginal size cost of QP is negligible against the correctness/simplicity win.

**MIME shape** (kept from the original, which is structurally correct): `multipart/mixed` [ `multipart/related` [ `multipart/alternative` [ text/plain, text/html ], inline CID images ], attachments ], with empty layers collapsed (no attachments → drop `mixed`; no inline images → drop `related`; single body → drop `alternative`).

**`-ContentDisposition` routing (the one genuine Lasso 8.5 → 9 incompatibility, §6):** `EmailMessage.defaultDisposition` supplies the fallback for attachments/inline resources that don't set their own `disposition`. The 8.5 overlay's top-level `-ContentDisposition` param sets `defaultDisposition`; Lasso 9's per-part `email_compose.addAttachment(-type:)` sets a per-attachment value directly — so the 8.5 param has a home even though Lasso 9 moved it off the top-level `email_send` signature.

### 4.8 Retry queue / error model

```swift
public struct EnhancedStatusCode: Sendable { public let clazz, subject, detail: Int }  // X.Y.Z, RFC 2034

public struct SMTPReply: Sendable {
    public let code: Int
    public let enhancedStatus: EnhancedStatusCode?
    public let lines: [String]
    public var replyClass: ReplyClass { /* mechanically derived from code: 2/3/4/5yz */ }
}

public enum SMTPError: Error, Sendable {
    case transientFailure(SMTPReply)       // 4yz other than 421 — retry per backoff schedule
    case serviceUnavailable(SMTPReply)     // 421 specifically — see corrected handling below
    case permanentFailure(SMTPReply)       // 5yz — MUST NOT retry
    case greylisted(SMTPReply)             // 450/451/452 first-contact — retry with delay
    case sizeExceeded(limit: Int)
    case authenticationFailed(SMTPReply)
    case starttlsRequired
    case starttlsInjection                 // the CVE-class buffer-discipline violation
    case tlsPolicyViolation(String)        // MTA-STS / DANE (Phase 4)
    case circuitOpen
    case connectionFailed(any Error)
    case ambiguousDelivery(SMTPReply?)     // failure AFTER 354/DATA, BEFORE 250 — point of no return
}

public struct DeliveryResult: Sendable {
    public let recipient: String
    public enum Outcome: Sendable {
        case delivered(SMTPReply)
        case queuedForRetry(nextAttempt: Date, attempt: Int, last: SMTPReply)
        case permanentlyFailed(SMTPReply)
        case expired(attempts: Int, last: SMTPReply)   // retry ceiling reached — see below
        case ambiguous(SMTPReply?)                     // surfaced, never auto-retried
    }
    public let outcome: Outcome
}
```

Classification is mechanical from `replyClass` (2/3/4/5yz), never guessed.

**`421` handled distinctly from greylisting — corrected (protocol review finding, required).** The original design folded all `4xx` into "normal, retry" (modeled on greylisting). This is wrong for `421` specifically: per RFC 5321 §3.8/§4.2.1, `421` means "service unavailable, closing the channel" — typically an overload/rate-limit signal — and treating it identically to a `450`/`451` greylist invites the exact aggressive-reconnection behavior that worsens the receiver's overload. Corrected: `421` closes the connection, feeds the circuit breaker for that destination, and uses a **longer** backoff than the greylist path; `450`/`451`/`452` remain the greylist path (minutes → hours, multi-day window).

**Retry ceiling — corrected (protocol review finding, required, previously unspecified).** The original design committed to "exponential backoff with jitter" but never stated a maximum age or attempt count, meaning transient failures would retry indefinitely rather than eventually resolving. Corrected: an explicit, configurable expiry (default: a bounded multi-day window, e.g. ~4-5 days, matching conventional MTA give-up behavior, plus a max-attempt cap) after which the outcome becomes `.expired`, distinct from `.permanentlyFailed` (a 5yz) so callers can distinguish "the destination actively rejected this" from "we gave up retrying a destination that kept saying try-again-later."

**Ambiguous delivery / idempotency (unchanged from the original design, confirmed sound by both reviews — do not weaken later):** the state machine tracks the "point of no return" — after the `354`/DATA payload is sent, before the `250` response is received. A failure in that window is `.ambiguous` and is **never** auto-retried (default policy: at-most-once, explicitly a caller-visible/configurable choice, not silently baked in) — a retry after an ambiguous failure risks double delivery, which the design correctly treats as the worse outcome to default against.

**Enhanced status parsing:** when `ENHANCEDSTATUSCODES` is advertised, each reply line's leading `X.Y.Z` token is parsed into `EnhancedStatusCode`, giving structured failure reasons (`5.1.1` = bad mailbox, `4.2.2` = mailbox full, etc.) far more useful than the bare 3-digit code for both logging and caller-facing diagnostics.

### 4.9 Public API sketch

**Modern Swift-native:**

```swift
let mailer = SMTPMailer(
    transport: .relay(RelayConfig(
        host: "smtp.sendgrid.net", port: 587, tls: .startTLS,
        auth: .plain(username: "apikey", password: apiKey))),
    dkim: DKIMSigner(domain: "example.com", selector: "s1",
                     signedHeaders: ["from", "to", "subject", "date", "message-id",
                                     "mime-version", "content-type"],
                     keys: [.rsa(pemKey)]))

var msg = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
msg.to = [EmailAddress(address: "user@dest.com")]
msg.subject = "Rësúmé"
msg.textBody = "hello"; msg.htmlBody = "<p>hello</p>"

let results = try await mailer.send(
    msg,
    bcc: ["hidden@example.com"],                 // Bcc supplied separately, never on EmailMessage
    envelopeFrom: .address("bounce@example.com")) // explicit reverse-path
```

**Batch send** — `try await mailer.send([msg1, msg2, …])` fans out via a **bounded** `TaskGroup` (concurrency review, required correction below), backpressured by the pool actor's per-host cap and NIO writability.

**Bounded batch fan-out — corrected (concurrency review finding, medium, required).** The original design relied entirely on the pool's internal suspension for backpressure ("bounded... backpressured by the pool actor's per-host cap"), but the pool only bounds *connections*, not *tasks*: a naive `for dest in destinations { group.addTask { ... } }` launches every child task eagerly, each capturing a full copy of the `SignedMessage` payload, so a large batch (e.g. 50,000 recipients across many destinations) would materialize 50,000 parked tasks and 50,000 message copies before a single connection frees up — unbounded memory and scheduler pressure entirely distinct from "connections are bounded." Corrected: add an explicit outer concurrency limiter using the sliding-window task-group pattern (prime N children, add one new child each time one completes), capping in-flight tasks to a configured maximum independent of (and typically larger than) the connection cap. This matters precisely at the scale an SMTP relay actually operates at, so it's required, not a later optimization.

**Streaming batch send** (added for list-server/bulk-mail use — see §8): `[EmailMessage]` requires the whole batch to be materialized in memory before sending starts, which doesn't hold up for a list server generating millions of per-recipient messages from a subscriber database. An `AsyncSequence`-based overload —

```swift
func send<S: AsyncSequence>(_ messages: S) async throws -> AsyncThrowingStream<DeliveryResult, Error>
    where S.Element == EmailMessage, S: Sendable
```

— lets a caller feed messages from a database cursor, a generator, or any other source without holding the whole recipient list in memory at once, while the same sliding-window-bounded fan-out (above) still caps in-flight work. This composes naturally with the "no Combine, `AsyncSequence` everywhere" direction already established for the wire protocol (§4.3): the caller supplies one `AsyncSequence` in, this API hands one back out, no separate reactive framework needed on either side. Suppression-list filtering (skipping recipients who unsubscribed or complained) is deliberately **not** an API this library exposes — that's caller policy, and an `AsyncSequence` input is already the natural place for a caller to filter its own stream before it ever reaches Perfect-SMTP, with zero extra surface needed here.

**Two-phase compose/sign/send:**

```swift
let composed = try MIMEComposer(msg, charset: "utf-8").compose()   // RFC5322Message, no send
let signed   = try dkim.sign(composed).frozen()
let results  = try await transport.send(envelope, signed)
```

**Async job/track — sketched here, never implemented (see the deferral note immediately below):**

```swift
let job = try await mailer.enqueue(msg)
let status = await mailer.status(of: job)   // .queued / .sent / .error
```

**`enqueue`/`status` deferral — recorded explicitly (milestone review, architecture pass, fix pass correction).** This section originally sketched `enqueue`/`status` as one of "the complete public surface of this package" alongside the three shapes that actually shipped, which became an inaccurate claim once Phase 0-5 landed without it. To be clear, now that all phases are complete: `enqueue`/`status` was never implemented in any phase, and nothing else in this design assumes it exists — no other phase's architecture, transport, or retry-queue logic depends on an async job-tracking layer being present. It is recorded here as a **deliberate, documented deferral**, matching this plan's established style for the DANE deferral and the MTA-STS stale-cache staleness-ceiling decision (§9, Phase 4): if durable job tracking is wanted in a future library or phase, it needs its own design pass — a persistence model (where job state lives across process restarts), a job-ID scheme, and an explicit decision on its relationship to `DirectMXRetryQueue`'s existing retry-state machine (§4.8/§9 Phase 3) — rather than being treated as a natural, low-effort extension of what shipped. `DirectMXRetryQueue` already gives synchronous callers structured per-recipient retry/expiry state; a durable, restart-surviving job-tracking API is a genuinely different, larger commitment (persistent storage, at minimum) that this rewrite never took on.

The actual, complete public surface of this package is: single-shot `send` (§4.9, above), array batch `send`, streaming `send` (the `AsyncSequence`-based overload, above), and two-phase compose/sign/send — four shapes, not three, correcting this section's original miscount, which also failed to mention the streaming overload documented in detail immediately above it. **There is no Lasso-facing entry point here** — see §4.1's correction. §6 documents, purely as reference research for a future, separate Perfect-Lasso-side task, how a `LassoPerfectSMTP`-style adapter (living in the Perfect-Lasso repo, not here) would map Lasso's `email_send` parameter surface onto these same four shapes.

## 5. Testing strategy

`swift-testing` throughout (not XCTest), matching this ecosystem's convention (`import Testing`, `@Test`, `#expect`). Injectable mocks in the Perfect-FileMaker `nonisolated(unsafe) static var` style where a protocol boundary needs one.

**Pure unit — `PerfectSMTPCoreTests`, runs in full on Linux, no BoringSSL required:**
- MIME builder byte-exact golden fixtures (mixed/related/alternative nesting, boundary generation, 76-column base64 wrap preserved from the original — the one thing it got right).
- **Bug regressions as first-class, named tests:** (a) a Bcc address supplied via `send(bcc:)` ends up in `SMTPEnvelope.recipients` and never in any serialized header, under `extraHeaders` too; (b) a non-ASCII subject is genuinely Q/B-encoded and round-trips correctly (the old `=?utf-8?Q?<raw>?=` output must fail this test).
- RFC 2047 correctness including the character-boundary-folding and quoted-string-exclusion corrections (§4.7).
- Dot-stuffing encoder (leading-dot doubling, terminal `.\r\n`).
- SASL PLAIN/LOGIN/XOAUTH2 base64 framing against known vectors.
- **DKIM against RFC 6376 Appendix A test vectors** (known key + message → known `b=`/`bh=`), both RSA and Ed25519 (RFC 8463 vectors) (RFC 6376 Appendix A's own worked example only reproduces its `c=simple/simple`-labeled `bh=` under relaxed canonicalization -- an independently-confirmed inconsistency in the RFC's own informative appendix, not an implementation bug -- so RFC 8463 Appendix A's internally-consistent republication of the same message is used as the byte-exact reference vector for both algorithms; see `Tests/PerfectSMTPCoreTests/DKIMRealVectorTests.swift`), including a test that an oversigned-but-absent header (§4.6) correctly invalidates the signature once that header is later injected.
- `ReversePath.null` serializes to exactly `MAIL FROM:<>`.
- Enhanced-status parser and the 2/3/4/5yz classifier, including `421` classifying separately from `450`/`451`/`452`.

(A Lasso address-list tokenizer — for the comma-delimited `-to`/`-cc`/`-bcc` splitting a future overlay needs — belongs to that future Perfect-Lasso-side task, §6, not this package's test suite.)

**Mocked NIO channel — `PerfectSMTPTests` via `EmbeddedChannel`:**
- Full state machine: multiline EHLO parse, PIPELINING batching vs. lock-step degradation **plus an equivalence test asserting both paths produce identical `[DeliveryResult]` for the same server script** (not merely "both code paths exist"), the mid-batch partial-RCPT-rejection behavior (§4.3), AUTH round-trips including XOAUTH2 token-refresh-on-535, SIZE pre-upload fail-fast on `552`, HELO fallback.
- **The STARTTLS buffer-discipline invariant as an automated regression** — the CVE-2026-41319-class test: feed `220 Ready\r\n` and a subsequent, separate injected read (`EHLO evil.example\r\n` as a **second** buffer, not concatenated) and assert `SMTPBootstrapHandler` throws `.starttlsInjection`, closes the channel, and never processes the injected command; a companion test confirms the clean single-`220`-then-silence path upgrades correctly and re-issues EHLO with capabilities reset.
- Phase B disconnect propagation: a mid-conversation channel closure must surface as a normal thrown error out of the actor's `for try await` loop over the `NIOAsyncChannel` inbound sequence — not hang. (This replaces the earlier "fail every outstanding promise in the queue" test that the original promise-correlation design needed; the corrected §4.3 design has no such queue to fail, so there's nothing to hang.)
- Pool cancellation: a `Task` cancelled while parked waiting for a connection slot resolves with `CancellationError` and is removed from the waiter queue without a double-resume against a concurrent `release()`.

**Gated live integration — `SMTP_TESTS=1`** (mirrors the `FILEMAKER_TESTS=1` convention): against a MailHog/smtp4dev CI service container (new `smtp` job in `.github/workflows/linux.yml`, mirroring the existing `redis` job), env `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASSWORD`. Verifies end-to-end submission, real STARTTLS handshake, AUTH PLAIN, and byte-intact receipt of the composed message.

## 6. Lasso 8.5 / Lasso 9 compatibility surface (reference only — NOT part of this package)

**This entire section documents research for a future, separate task that belongs in the Perfect-Lasso repository, not in Perfect-SMTP.** Nothing described here is part of this plan's deliverable, is present in `Package.swift`, or is implemented by any phase in §9 — Perfect-SMTP has no Lasso-shaped types, no dash-param API, and no knowledge that Lasso exists (§4.1). It's kept here because the research (verified against the actual local PDF and lassoguide.com, not assumed) is valuable groundwork for whoever eventually builds a `LassoPerfectSMTP`-style adapter in `/Users/timtaplin/Perfect-Lasso/Sources/`, structured the same way `LassoPerfectFileMaker`/`LassoPerfectCRUD` already are there — consuming this package's plain public API (§4.9) from the outside, exactly as any other Swift caller would.

Both Lasso versions ship a built-in, first-class, near-identically-named email API — **`[Email_Send]`** (Lasso 8.5, *Lasso 8.5 Language Guide.pdf*, Chapter 47, pp. 587-600) and **`email_send`** (Lasso 9, lassoguide.com — same name, now a method). This is not ambiguous or an external-binding case; both are fully documented, first-class built-ins. Lasso 9 kept essentially every 8.5 parameter name verbatim (lowercased), which is very favorable for a Lasso-9-primary, 8.5-overlay design.

There is **no `Send_Mail` tag** in Lasso 8.5 — the Language Guide explicitly states the pre-8.0 `-Email.*` dash-command syntax "will not operate in Lasso 8" and "`[Email_Send]`" is the only way to send email in 8.5+. Any corpus code using older syntax predates 8.5 compatibility entirely.

**Full shared parameter surface** (identical semantics in both versions — the overlay maps these essentially 1:1): `-to`/`-from`/`-subject` (from+subject always required, one of to/cc/bcc required), `-body`/`-html` (one required, both → multipart/alternative), `-cc`/`-bcc`, `-htmlImages` (array of paths OR array of `name=data` pairs, `cid:` or `src`-matched), `-attachments` (array of paths OR `name=data` pairs, base64-encoded, both versions document an 8MB total-size ceiling for this send path), `-tokens`/`-merge` (mail merge), `-priority` (`High`/`Low`, default `Medium`), `-replyTo`, `-sender`, `-contentType`/`-transferEncoding`/`-characterSet` (raw header overrides — neither version documents a default, filled by this rewrite per §4.7), `-extraMIMEHeaders`, `-immediate`, `-host`/`-port` (default 25)/`-username`/`-password`/`-timeout`.

**Lasso-9-only additions** (native in the modern API; the 8.5 overlay simply never sets them): `-ssl` (boolean, undifferentiated implicit-vs-STARTTLS — see §4.9's mapping decision), `-date` (schedule a future send), `-simpleform` (send with no body), and on the low-level `email_smtp` type, `-clientIp` (HELO/EHLO identity control) and `-multi`.

**The one genuine 8.5 → 9 incompatibility:** 8.5's `-ContentDisposition` (default `'attachment'`) exists directly on `[Email_Send]`; Lasso 9 moved it to the `email_compose` type only, dropped from `email_send`'s own top-level params. Resolved in §4.7 by routing it to `EmailMessage.defaultDisposition` regardless of which Lasso version's overlay sets it.

**Multi-recipient encoding — confirmed, load-bearing for the overlay's correctness (§4.9):** both versions explicitly document that `-to`/`-cc`/`-bcc` are always a single comma-delimited string ("Multiple -To, -CC, or -BCC parameters are not allowed," 8.5 Language Guide p. 590) — never repeated params, never a native Lasso array for these three fields specifically (unlike `-htmlImages`/`-attachments`, which do take arrays).

**Companion API surface** the overlay's shape should stay compatible with, without needing full parity immediately: `email_compose` (build-then-send two-phase API — directly mirrored by §4.9's two-phase compose/sign/send sketch), `email_smtp` (a low-level connection type — `->open`/`->command(-send,-expect,-multi,-read)`/`->send`/`->close` — maps closely to this design's `SMTPConnection` handle, worth keeping shaped similarly), `email_mxlookup(domain, -refresh, -hostname)` (direct precedent for the Phase 3 direct-MX transport's public shape, including a `priority` field matching MX preference ordering), `email_result`/`email_status` (async job ID + polling — direct precedent for and validation of this design's `enqueue`/`status(of:)` API, since Lasso's own email model has always been queue-based, not fire-and-forget-synchronous).

## 7. Concrete gaps in the decades-old implementation vs. modern email delivery requirements

Everything below is either entirely absent from the current `Perfect-SMTP` or only present because libcurl silently handled it. Ranked by real-world impact; each maps directly to a requirement in §4 or a phase in §9.

**Critical — correctness/security:**
- No STARTTLS state machine of its own, no buffer-discipline guarantee against the CVE-2026-41319-class injection/downgrade attack (§4.3).
- No STARTTLS-vs-plaintext enforcement policy, no MTA-STS/DANE (Phase 4) — opportunistic-only via a bare flag today.
- Bcc header leak (§1, fixed §4.7).
- Fake quoted-printable subject encoding (§1, fixed §4.7).
- No AUTH mechanism control; bare username:password cannot authenticate to Gmail/Workspace at all (OAuth-only since March 2025) and will lose Microsoft 365 access as Basic-auth SMTP is phased out through 2027 (§4.5).

**High — delivery correctness / "primary point of delivery" is currently impossible:**
- No MX resolution, no preference ordering, no null-MX (RFC 7505) handling, no A/AAAA fallback (§9 Phase 3).
- No retry queue at all — `send()` is one blocking attempt; a `451` greylist response (a *normal*, expected first-contact behavior from many receivers) looks identical to a hard failure today (§4.8).
- No DKIM signing — without a relay in front, unsigned mail from a direct sender fails DMARC alignment at Gmail/Yahoo and is rejected or junked (§4.6).
- No envelope-from as an explicit, caller-controlled field — blocks SPF/DMARC alignment entirely (§4.7).
- Everything is single-threaded and blocking — no pooling, no pipelining, no concurrency of any kind (§4.3, §4.4).
- No per-destination rate limiting or circuit breaking — direct delivery at any real volume would get the sender rate-limited or blocklisted (§4.4).

**Medium — robustness/interop, currently entirely libcurl's problem, invisible to this library:**
- No SIZE/8BITMIME/SMTPUTF8/PIPELINING/CHUNKING capability handling — the library has no idea what the server supports (§4.3).
- No DSN request/parsing, no enhanced-status-code parsing — failures surface only as a bare code + body string today (§4.8).
- No distinction between implicit TLS (465) and STARTTLS (587) — just one `.useSSL` flag (§4.3).
- No explicit per-command timeouts of its own (§7, below).
- No internationalized-address (SMTPUTF8/IDNA) handling.
- **No configurable EHLO/HELO hostname** (protocol review finding, required addition) — direct-to-MX receivers widely reject or penalize a HELO identity that isn't a resolvable FQDN matching the sending IP's reverse-DNS/PTR record; the current code never announces one at all (libcurl picks something). Required: an explicit, caller-configurable EHLO hostname, documented as needing correct forward+reverse DNS for direct-MX delivery to work at all.
- **No per-command timeouts** (protocol review finding, required addition) — RFC 5321 §4.5.3.2 specifies minimum client timeouts per command phase (e.g. 5 min for MAIL/RCPT, 10 min for the DATA terminating dot); without them, a hung remote server pins a pooled connection indefinitely. Required: explicit, phase-specific timeouts feeding the transient-failure classification.
- **No guaranteed `Date`/`Message-ID` synthesis** (protocol review finding, required addition, though the original code did get `Message-ID` right) — both are effectively required for acceptance by modern receivers; `EmailMessage.date`/`.messageID` must be auto-synthesized when the caller leaves them unset, with the Message-ID domain scoped to the DKIM `d=`/envelope-from domain for coherence (§4.7).

**Lower — deliverability hygiene, genuinely required as of 2024-2025 bulk-sender rule changes, not just nice-to-have:**
- No List-Unsubscribe/List-Unsubscribe-Post headers (RFC 8058) — Gmail and Yahoo have enforced this with outright rejections for bulk senders since November 2025; this is now a hard requirement for any bulk-sending use case, not an optional nicety (Phase 5).
- No Precedence/Auto-Submitted headers (RFC 3834) for automated/bulk mail — cheap to add, improves interop and loop-avoidance (Phase 5).

## 8. List-server / bulk-mail readiness

Explicitly raised as a design goal — this section confirms what's already covered elsewhere in this plan, adds one concrete API addition, and draws an explicit scope boundary around what a list server or similar mail utility would still need to build on top.

**Already covered by earlier sections, not restated in full here:**
- DKIM signing (§4.6), the single biggest deliverability lever for a sender operating at any real volume.
- List-Unsubscribe/-Post and Precedence/Auto-Submitted headers (§7, Phase 5) — the specific 2024-2025 Gmail/Yahoo bulk-sender requirements.
- Per-destination rate limiting and circuit breaking (§4.4) — necessary to avoid tripping receiver-side abuse detection when sending to many recipients at the same provider.
- PIPELINING (§4.3) and connection pooling/reuse (§4.4) — the actual throughput levers for high-volume sending; a list server whose subscriber base clusters at a handful of large providers (Gmail, Outlook, Yahoo) benefits directly from the pool's per-destination-host keying, since many recipients at the same provider can share pooled, pipelined connections rather than each opening a fresh one.
- The retry queue's transient/permanent/greylist/expired classification (§4.8) — gives a list server structured, actionable delivery results per recipient rather than a single pass/fail.

**New addition — streaming batch input (§4.9):** the `AsyncSequence`-based `send<S: AsyncSequence>(_:)` overload exists specifically so a list server can stream messages generated from a subscriber database or similar source without materializing the entire recipient list in memory at once. This is the one concrete design change this readiness review produced.

**Explicitly out of scope — a different, receiving-side problem:** bounce and complaint *processing* (parsing inbound bounce messages, handling ISP Feedback-Loop/ARF reports, updating a suppression list from them) requires *receiving* mail — either polling a bounce mailbox via IMAP/POP or running a receiving SMTP service — which is categorically different work from the sending client this plan describes. Perfect-SMTP's responsibility ends at structured delivery results for failures the *receiving MTA reports synchronously during the SMTP conversation itself* (§4.8); asynchronous bounce/complaint reports that arrive later through a separate channel are not something an SMTP-sending library can observe at all, let alone process. A list server needs this capability, but it belongs in a separate tool or a future library, not in Perfect-SMTP. Similarly, subscriber-list management, unsubscribe-request handling, and suppression-list storage are all caller-side application concerns (as already noted in §4.9's streaming-send section) — deliberately not something this library takes a position on.

## 9. Phasing

Matches this ecosystem's own branch-per-phase convention. Each phase is independently shippable and gets its own feature branch, its own review pass, its own test suite run, before merging.

- **Phase 0 — Core model & MIME (low risk).** Package skeleton (2 targets — `PerfectSMTPCore`, `PerfectSMTP`; no Lasso-aware target, see §4.1), `EmailMessage`/`SMTPEnvelope`/`ReversePath`/address types, `MIMEComposer`, the corrected RFC 2047 `HeaderEncoder`, dot-stuffing, base64/QP encoders, reply/error/result types. **Both original bugs are fixed here**, structurally, with the corrected specs from §4.7. Full Core unit suite, including the DKIM RFC 6376 test vectors (signer itself lands in Phase 2, but the vector-checking harness can be built here). Independently shippable as a pure message-building library.
- **Phase 1 — Relay + local-MTA transports (medium-high risk, security-critical).** Both top-level "delegate to an already-operated MTA" strategies ship together, per §3's elevation: `RelayTransport` — the two-phase bootstrap/`NIOAsyncChannel` design (§4.3, a minimal explicit handler for connect/EHLO/STARTTLS only, native `async`/`await` for everything else, no hand-rolled promise-correlation queue), `SMTPResponseDecoder`, EHLO/capabilities, implicit TLS (465) + STARTTLS with the corrected buffer-discipline sequence and its automated regression test, AUTH PLAIN/LOGIN/XOAUTH2 with token-refresh, SIZE/8BITMIME/PIPELINING (including the corrected partial-rejection semantics), the connection pool with the corrected reentrancy/cancellation/shutdown discipline (§4.4), `SMTPMailer.send` with the corrected bounded-batch fan-out — plus `LocalMTATransport`, the async-safe `sendmail`/`postfix -t` `Process` wrapper (needs its own careful design: a single-resume guard bridging `terminationHandler` to a continuation, concurrent stdout/stderr draining to avoid a pipe-buffer deadlock, and confinement behind an actor since `Foundation.Process` is not `Sendable`). **This is the first genuinely usable release** and directly replaces the libcurl-based implementation, giving operators who already run their own MTA a fully-working option immediately rather than waiting on the harder phases below.
- **Phase 2 — DKIM signing (medium risk, self-contained).** `DKIMSigner`, RSA-SHA256 + Ed25519 dual-sign, the corrected oversigning-of-absent-headers behavior, DMARC-alignment lint. Makes the "primary delivery" story viable at all, and improves deliverability for `RelayTransport` senders too.
- **Phase 3 — Direct-MX transport (high risk, the most novel engineering in this plan).** Hand-rolled MX/A/AAAA resolver over NIO UDP (no official SSWG resolver exists — this is the single largest item in the whole plan), preference ordering + equal-preference randomization, null-MX hard-fail, IPv4+IPv6, retry-queue actor with the corrected 421-vs-greylist distinction and the corrected retry-ceiling/expiry (§4.8), circuit breaker, multi-host pool, ambiguous-delivery handling (already correct from Phase 1, just exercised at scale here). Only needed by operators who want Perfect-SMTP itself to be the terminal MTA rather than delegating to Phase 1's relay/local-MTA transports.
- **Phase 4 — TLS verification policy (high risk, scope explicitly narrowed at the start of this phase, per below).** MTA-STS policy fetch + cache, `enforce`-mode hard-fail, plus closing the opportunistic-TLS gap Phase 3 explicitly deferred here (`DirectMXConfig.tls`'s original doc comment). **DANE/TLSA scope decision (made explicitly, not silently, per this phase's own brief): DANE is deferred entirely — this phase ships MTA-STS only.** Rationale: Phase 3's `DNSResolver` (`Sources/PerfectSMTP/DNS/DNSResolver.swift`) explicitly does not perform DNSSEC validation — itself an explicit Phase 3 scope decision (see that file's header comment: "no DNSSEC validation... a validating resolver is a distinct, larger concern explicitly flagged there as a likely scope-narrowing candidate"). Fetching DANE/TLSA records without DNSSEC validation would provide *false* security assurance: an on-path attacker could spoof or strip TLSA records undetected, and a caller might believe they have DANE protection when they don't — that would be actively worse than not implementing DANE at all, not a neutral partial win. Real-world MTAs treat a genuinely DNSSEC-validating resolver as a hard prerequisite for DANE (e.g. Postfix's DANE support is opt-in and documented as requiring a validating resolver configured upstream) — this isn't an unusual or overly conservative industry position. Building a real DNSSEC validator (chain-of-trust from root, DS/DNSKEY following, RRSIG verification) is a substantially larger undertaking than Phase 3's entire hand-rolled DNS resolver and is out of scope for this rewrite. If DANE is ever revisited in a future phase, it must be built on top of a genuinely DNSSEC-validating resolver (either hand-rolled, a substantial project of its own, or delegated to a trusted local validating resolver via a documented constraint) — never layered on top of this package's own non-validating `DNSResolver` as-is. Per RFC 8461's own text and general best practice, that future DANE work must also ensure a DANE failure is never overridden by an MTA-STS pass for the same connection (DANE is the stronger signal when both are present for a domain) — see the forward-looking note on `MTASTSPolicy` (`Sources/PerfectSMTP/MTASTS/MTASTSPolicy.swift`). **Stale-cache staleness-ceiling decision (made explicitly, per the post-milestone-review fix pass, and named the same deliberate way as the DANE deferral above): `MTASTSPolicyManager.policy(for:)`'s cached-policy fallback on a discovery/fetch/parse failure is bounded by `Configuration.staleCacheCeiling` (default 5 days past the cached policy's own `expiresAt`), not indefinite.** RFC 8461 §3.3 (fetched and verified directly against the published RFC text during this fix pass, not assumed) gates cached-policy fallback on the cached policy being "valid (non-expired)" — the previous implementation's doc comment instead cited a nonexistent "§5.1 anti-flapping" rule (no such text exists anywhere in RFC 8461) to justify falling back to a cached policy indefinitely, regardless of how long past its own `max_age` that policy was. That is a real availability bug, not a harmless simplification: a domain that legitimately decommissions MTA-STS (removes its `_mta-sts` TXT record and well-known policy file, e.g. after a hosting/DNS migration) would have this sender continue enforcing its old, abandoned `enforce` policy forever, since a DNS discovery failure was folded into the same fallback path as an ordinary HTTPS fetch failure — if the domain's new MX hosts don't match the stale policy's `mx:` patterns, this permanently and silently blocks delivery with no recovery path. `staleCacheCeiling` is this library's own explicit, reviewed policy decision (RFC 8461 specifies no shape for how long an already-expired policy may still influence delivery) — its default deliberately mirrors `DirectMXRetryQueue.Configuration.maxAge`'s own 5-day default and rationale (conventional MTA give-up windows), for consistency across this codebase's two "how long do we keep trusting stale state" decisions, not because the RFC mentions that number. Once a cached policy is past that ceiling and a refresh attempt fails, the domain reverts to policy-less — matching RFC 8461 §3.3's literal "non-expired" gating — rather than continuing to enforce a policy that may no longer reflect the domain's real MTA-STS posture at all. See `Sources/PerfectSMTP/MTASTS/MTASTSPolicyManager.swift`'s `Configuration.staleCacheCeiling` doc comment for the full detail.
- **Phase 5 — Deliverability hygiene (low-medium risk).** List-Unsubscribe/-Post + Precedence/Auto-Submitted headers, and the streaming batch-input API (§8, "list-server readiness"). **This is the last phase of Perfect-SMTP itself.** A Lasso-compatibility adapter (§6) is explicitly out of scope for all phases of this plan — it is separate future work in the Perfect-Lasso repository, not a phase of Perfect-SMTP, and has no bearing on when Perfect-SMTP's own phases are considered complete.

## 10. Review record

This plan is the output of a full design → review cycle, not a single pass:

1. **Research** — modern SMTP/RFC/deliverability requirements (RFC-cited, web-verified against 2025-2026 provider policy changes) and Lasso 8.5/9 email-tag semantics (verified against the actual local PDF and lassoguide.com, not assumed), run in parallel.
2. **Transport-options review** — adopt-vs-build-vs-wrap-vs-shell-out, with live verification of third-party library candidates (platform support, feature completeness) rather than assumption. Result: hand-roll on NIO behind a pluggable `Transport` abstraction (§3).
3. **Application-architect design pass** — produced the full architecture in §4, grounded in this ecosystem's actual established conventions (read from Perfect-NIO, Perfect-Notifications, Perfect-FileMaker directly, not inferred).
4. **Swift-concurrency-expert review** (using this project's `swift-concurrency-pro` skill) — found one critical data race (the promise-correlation queue as originally specified) and several required-but-unspecified behaviors (cancellation handling, shutdown draining, reentrancy discipline, bounded batch fan-out). All findings are folded into §4 as corrected, authoritative specification, not left as open review comments.
5. **SMTP-protocol/adversarial review** — confirmed the DKIM ordering and STARTTLS capability-reset logic as sound, and found several protocol-correctness gaps (quote-unaware address splitting, missing null-return-path handling, an incomplete STARTTLS timing guarantee, under-specified RFC 2047 folding, the 421-vs-greylist conflation, missing EHLO-hostname/timeout/Message-ID requirements, incomplete DKIM oversigning semantics, and untested PIPELINING partial-failure behavior). All findings are likewise folded into §4/§7/§9 as corrected specification.

Every finding from both review passes is either (a) resolved in the corrected design text above, or (b) explicitly carried forward as a named open decision in §9's phasing (DANE/DNSSEC scope -- **resolved at the start of Phase 4: DANE deferred entirely, MTA-STS only, see §9's Phase 4 bullet for the full rationale** -- CRAM-MD5/SCRAM deprioritization pending a swift-crypto PBKDF2 check, the `_RSA.Signing.PrivateKey` Sendable-conformance check). Nothing was silently dropped.

## 11. Process notes

- All implementation work happens on feature branches (this plan document itself was written on `swift6-nio-rewrite-plan`, branched from `master`); no phase merges to `master` without its own build+test+review pass, matching this project's established discipline elsewhere in the Perfect-Resurrection ecosystem.
- No other Perfect-Resurrection library needs any change as a prerequisite for this work (§2).
- **Perfect-SMTP itself never depends on, imports, or references Perfect-Lasso, and has no target shaped around Lasso's parameter surface** (§4.1). When Perfect-Lasso wants email-sending support, that work happens entirely on the Perfect-Lasso side: a new target there (analogous to `LassoPerfectFileMaker`/`LassoPerfectCRUD`, e.g. `LassoPerfectSMTP`) takes a plain dependency on this package's public `PerfectSMTP` product and maps Lasso's `email_send` dash-params onto it, using §6 as reference research. That task is out of scope for this plan and is not tracked as one of its phases.
- **On the future/promise question raised during review:** the public API is `async`/`await` throughout with no `EventLoopFuture` crossing any package boundary. Internally, `EventLoopPromise` is used only within the small, explicit Phase-A bootstrap handler (§4.3) for the connect/EHLO/STARTTLS sequence, where NIO's event-loop-driven pipeline genuinely requires it — one promise at a time, never a queue. The bulk conversation (Phase B, everything after the channel is TLS-ready) is driven by `NIOAsyncChannel`'s native `AsyncSequence`/`AsyncIterator` API, matching Perfect-NIO's own established pattern (`WebSocketHandler.swift`, `NIOAsyncHTTPHandler.swift`) rather than introducing a second, competing concurrency style. No Combine anywhere — ruled out categorically by this ecosystem's Linux-compatibility requirement, and unnecessary given structured concurrency (`TaskGroup`, actors, `AsyncSequence`) covers every queue/stream need this design has.

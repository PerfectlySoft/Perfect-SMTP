# Perfect-SMTP User Guide

This is the deep-dive reference for Perfect-SMTP. If you just want to send
one email, start with the [README quick start](../README.md#quick-start);
come back here for anything beyond that.

Every claim in this guide is grounded in the actual shipped code on `main`
(not the original design sketches in
`Documentation/swift6-nio-rewrite-plan.md`, which describes the design
intent but was written before several review passes changed the final
API). Where it's useful to cite the plan for background/rationale, this
guide says so explicitly.

## Contents

- [Sending your first email](#sending-your-first-email)
- [Choosing a transport](#choosing-a-transport)
- [Authentication](#authentication)
- [DKIM signing](#dkim-signing)
- [MTA-STS and TLS policy](#mta-sts-and-tls-policy)
- [Sending in bulk / list-server use](#sending-in-bulk--list-server-use)
- [Deliverability headers](#deliverability-headers)
- [Handling delivery results and retries](#handling-delivery-results-and-retries)
- [Testing your integration](#testing-your-integration)
- [Migrating from the old Perfect-SMTP](#migrating-from-the-old-perfect-smtp)

## Sending your first email

Every send goes through the same four pieces:

1. An `EmailMessage` — the *content*: headers and body, but deliberately no
   routing information (no Bcc field — see
   [Deliverability headers](#deliverability-headers) and
   [Migrating](#migrating-from-the-old-perfect-smtp) for why).
2. A `SMTPTransport` — *how* the message actually leaves your process (see
   [Choosing a transport](#choosing-a-transport)).
3. A `SMTPMailer` — glues a transport (and, optionally, a DKIM signer)
   together into the thing you actually call `send` on.
4. A `ReversePath` — the SMTP envelope's `MAIL FROM`, supplied separately
   from the message's `From:` header.

```swift
import PerfectSMTP
import NIOPosix

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

let transport = RelayTransport(
    config: RelayConfig(host: "smtp.example.com", port: 587, tls: .startTLS),
    group: group
)
let mailer = SMTPMailer(transport: transport)

let from = EmailAddress(displayName: "Storefront", address: "orders@example.com")
let to = EmailAddress(displayName: "Jane Doe", address: "jane@dest.com")

var message = EmailMessage(from: from)
message.to = [to]
message.subject = "Your order has shipped"
message.textBody = "Plain-text body."
message.htmlBody = "<p>HTML body.</p>"

let results = try await mailer.send(
    message,
    bcc: ["audit@example.com"],
    envelopeFrom: .address("bounce@example.com")
)

for result in results {
    switch result.outcome {
    case .delivered(let reply):
        print("\(result.recipient): delivered, \(reply.code)")
    case .queuedForRetry(let nextAttempt, let attempt, _):
        print("\(result.recipient): retry #\(attempt) at \(nextAttempt)")
    case .permanentlyFailed(let reply):
        print("\(result.recipient): permanently failed, \(reply.code)")
    case .expired(let attempts, _):
        print("\(result.recipient): expired after \(attempts) attempts")
    case .ambiguous:
        print("\(result.recipient): ambiguous, do not retry")
    case .failed(let error):
        print("\(result.recipient): transport error \(error)")
    }
}

try await group.shutdownGracefully()
```

A few things worth calling out:

- **`EmailAddress`** is a display name (optional) plus the bare `addr-spec`
  (`jane@dest.com`), stored separately so the header encoder can apply RFC
  2047 encoding to the display name without ever touching the address
  itself.
  The address has to be a plain mailbox (`local@domain`: a dot-atom local
  part, and an LDH domain or an `[address literal]`), checked by
  `AddressSyntax`. Quoted local parts, `<`, `>`, whitespace and control
  characters are refused, and so are non-ASCII addresses: SMTPUTF8 isn't
  implemented yet, so convert an internationalized domain to its A-label
  (`xn--...`) form first.
- **`bcc:` is a parameter of `send`, not a field on `EmailMessage`.** This
  is a deliberate structural fix (see
  [Migrating](#migrating-from-the-old-perfect-smtp)): Bcc addresses become
  extra `RCPT TO` entries in the envelope and are never serialized into any
  header sent to any recipient.
- **`envelopeFrom` is a `ReversePath`, not a plain string** — either
  `.address("bounce@example.com")` or `.null` (the RFC 5321 §4.5.5
  `MAIL FROM:<>` bounces/DSNs/auto-replies require). Modeling it as an enum
  instead of a `String` means the null return-path is representable and
  the serializer guarantees it — a plain string couldn't guarantee either.
- **`DeliveryResult`** is one entry per recipient (`to` + `cc` + `bcc`, all
  flattened into the envelope's `RCPT TO` list), each with its own
  `Outcome` — see
  [Handling delivery results and retries](#handling-delivery-results-and-retries)
  for what each case means and what you should do about it.

## Choosing a transport

Perfect-SMTP ships three `SMTPTransport` implementations. `SMTPMailer` is
generic over `any SMTPTransport`, so the same message-composition and
DKIM-signing pipeline works identically regardless of which one you pick.

| Transport | Use it when... |
|---|---|
| `RelayTransport` | You already have an SMTP host to hand mail to — a commercial ESP (SendGrid, Postmark, SES) or a self-hosted/internal relay (a corporate Postfix/Exim), with or without AUTH. |
| `LocalMTATransport` | You already run a hardened MTA (Postfix, sendmail, Exim) on the *same host* as your process, and want to hand off via the `sendmail`-compatible command-line interface — the same integration point PHP's `mail()` and countless other runtimes use. |
| `DirectMXTransport` | You want Perfect-SMTP itself to be the terminal MTA: it resolves the recipient domain's MX records and delivers straight to them, with its own retry queue, circuit breaker, and (optionally) MTA-STS enforcement. |

### `RelayTransport`

```swift
let config = RelayConfig(
    host: "smtp.sendgrid.net",
    port: 587,
    tls: .startTLS,
    auth: .plain(username: "apikey", password: "SG.xxxx"),
    ehloHostname: "mail.example.com"
)
let transport = RelayTransport(config: config, group: group)
let mailer = SMTPMailer(transport: transport)
```

`RelayTransport` owns a pooled connection to exactly one configured host
(`SMTPConnectionPool`, keyed by host/port/TLS mode), authenticating each
freshly-dialed connection once and reusing it across sends. `tls` is a
`TLSMode`: `.none` (plaintext — fine on a trusted internal network),
`.startTLS` (explicit upgrade, typically port 587 — mandatory once
requested: if the server doesn't advertise STARTTLS, the connection fails
rather than silently continuing in plaintext), or `.implicit` (TLS from the
first byte, typically port 465). Both TLS modes verify the server's
certificate chain and hostname.

`tls: .none` together with `auth` is refused: `send` throws
`RelayTransportError.authenticationRequiresTLS` before opening a
connection, so credentials are never sent in cleartext by accident. For a
relay you trust (a loopback MTA, a MailHog/smtp4dev test server that wants
AUTH), opt in with `allowsAuthenticationWithoutTLS: true`.

### `LocalMTATransport`

```swift
let config = LocalMTAConfig(executablePath: "/usr/sbin/sendmail")
let transport = LocalMTATransport(config: config)
let mailer = SMTPMailer(transport: transport)
```

This composes a correct, DKIM-signable message and hands it to the local
MTA binary via `Process`, passing the envelope recipients as explicit
trailing arguments (never via a `-t`-style "read recipients from headers"
flag, so `SMTPEnvelope.recipients` — including Bcc — stays the single
source of truth for who actually receives the message). From that handoff
onward, delivery, retries, and TLS are entirely the local MTA's
responsibility, not this library's — a `.delivered` result from this
transport means only "the local MTA accepted the handoff," not
"the recipient's mailbox actually got it."

### `DirectMXTransport`

```swift
let resolver = DNSResolver(group: group)
let config = DirectMXConfig(
    tlsPolicy: .opportunistic,
    ehloHostname: "mail.example.com",
    allowPrivateAddresses: false
)
let transport = DirectMXTransport(resolver: resolver, config: config, group: group)
let mailer = SMTPMailer(transport: transport)
```

`DirectMXTransport` groups a send's recipients by destination domain,
resolves each domain's MX records (falling back to the domain's own
A/AAAA records per RFC 5321 §5.1 if there are no MX records, and hard-
failing immediately on an RFC 7505 null-MX record), and delivers to each
domain independently — one domain's failure never affects another's.

Two things worth understanding before you point this at real recipients:

- **`allowPrivateAddresses` defaults to `false` for a real reason.** This
  transport dials whatever addresses a destination domain's DNS records
  publish. If your recipient domain is ever influenced by an untrusted
  party (a "share via email" feature, anything where the destination
  domain isn't fully under your own control), an attacker could publish MX/
  A/AAAA records pointing at `127.0.0.1`, an RFC 1918 address, or other
  internal infrastructure — this is a real SSRF vector, not a theoretical
  one. With the default `false`, every resolved address is checked and
  private/loopback/link-local/unique-local/CGNAT addresses are dropped
  before this transport ever opens a connection to them. Only set it `true`
  for a deliberate internal-relay-testing setup.
- **`tlsPolicy` defaults to `.opportunistic`**, not `.fixed(.none)` — see
  [MTA-STS and TLS policy](#mta-sts-and-tls-policy) below for exactly what
  that means.
- `DirectMXTransport` owns its own retry queue and circuit breaker — see
  [Handling delivery results and retries](#handling-delivery-results-and-retries).

## Authentication

`RelayConfig.Auth` covers three SASL mechanisms, all conforming to
`SASLMechanism`:

```swift
.plain(username: "user", password: "pass")   // SASLPlain, RFC 4616
.login(username: "user", password: "pass")   // SASLLogin, RFC 4954's de facto AUTH LOGIN
.xoauth2(username: "user@example.com", tokenProvider: {
    try await fetchFreshAccessToken()          // your own OAuth2 token-refresh logic
})
```

`PLAIN` and `LOGIN` are the workhorses for ESPs that issue an API key as an
SMTP password (SendGrid, Postmark, SES). `XOAUTH2` (RFC 7628) is
effectively mandatory for Gmail/Workspace — legacy SMTP password auth has
been disabled there since March 2025 — and is being phased in as a
requirement for Microsoft 365 as Basic-auth SMTP is phased out through
2027. Perfect-SMTP only formats the XOAUTH2 wire framing and calls your
`tokenProvider` closure; it does not run an OAuth2 authorization flow
itself, so you still need your own token-acquisition/refresh logic (a
`ASAuthorizationController`-style flow, a stored refresh token, whatever
fits your app). On a `535` authentication failure, the connection calls
`tokenProvider()` again and retries the exchange once before surfacing
`SMTPError.authenticationFailed` — useful if your provider returns a
just-expired token.

`SASLCramMD5`/`SASLScramSHA256` are not implemented (deliberately deferred,
per the rewrite plan).

AUTH is only sent over TLS unless you set
`RelayConfig.allowsAuthenticationWithoutTLS` (see
[`RelayTransport`](#relaytransport)). `RelayConfig.Auth`, `SASLPlain` and
`SASLLogin` print redacted descriptions, so logging a configuration never
prints the password.

## DKIM signing

```swift
let signer = try DKIMSigner(
    domain: "example.com",
    selector: "s1",
    signedHeaders: ["from", "to", "subject"],
    keys: [try SigningKey.rsa(pem: rsaPrivateKeyPEM)]
)
let mailer = SMTPMailer(transport: transport, signer: signer)
```

`DKIMSigner` implements RFC 6376 (RSA-SHA256) and RFC 8463
(Ed25519-SHA256), and conforms to the `MessageSigner` seam `SMTPMailer`
accepts — pass one to `SMTPMailer.init(transport:signer:)` and every send
through that mailer gets a `DKIM-Signature` header prepended automatically.

**Keys.** `SigningKey.rsa(pem:)` parses a PEM-encoded RSA private key and
enforces the RFC 6376 §3.3.3 2048-bit minimum (a key below that throws).
`SigningKey.ed25519(rawRepresentation:)` takes a raw 32-byte Ed25519 key.
Pass one key for single-algorithm signing, or two — one `.rsa`, one
`.ed25519` — to dual-sign (two independent `DKIM-Signature` headers,
neither signing the other).

**`signedHeaders`** is your base list of headers to include in the
signature's `h=` tag. You don't need to list `From`, `Subject`, `To`, `Cc`,
`Date`, `Reply-To`, `Sender`, `Content-Type`, `MIME-Version`,
`List-Unsubscribe`, or `List-Unsubscribe-Post` yourself — those are
**always oversigned automatically** (`DKIMSigner.alwaysOversignedHeaders`).

**What oversigning means and why you don't configure it.** RFC 6376's `h=`
tag lists which headers are covered by the signature, but a header that
occurs zero times in the message can still be listed — that's oversigning.
If a header is oversigned with a count one higher than its actual
occurrences (including a *phantom* entry for a header that isn't present
at all), an attacker who later injects that header (for example, adding a
second `From:` or a `Bcc:` to a message in transit) breaks the signature,
because the receiver's verifier now sees one more occurrence of that
header than the signature accounted for. Perfect-SMTP applies this
automatically to the header list above on every signed message — including
`Bcc`, which this library structurally never emits itself (there is no
`bcc` field on `EmailMessage` at all), making it a "free" defensive
signature entry with no cost. `List-Unsubscribe`/`List-Unsubscribe-Post`
are oversigned for the same reason and because RFC 8058 §4 requires them
to be DKIM-covered for Gmail/Yahoo to honor one-click unsubscribe at all —
if you set `EmailMessage.listUnsubscribe` and sign with a `DKIMSigner`,
this coverage happens without you needing to add those names to
`signedHeaders` yourself.

**DMARC alignment.** After composing and signing, `SMTPMailer` checks
whether the signer's `d=` domain aligns with the message's `From:` domain
(RFC 7489 §3.1.1's relaxed alignment — same Organizational Domain, checked
in both directions) and logs a warning (via the `logger` passed to
`SMTPMailer.init`) if it doesn't. This never blocks sending — misalignment
is sometimes intentional (third-party sending infrastructure) — it's
purely a diagnostic. Note this is a heuristic, not a full Public Suffix
List implementation: it correctly handles the common case (a registrable
domain used directly as `d=`) and a small explicit denylist of known bare
public suffixes (`com`, `co.uk`, etc.), but isn't PSL-complete.

## MTA-STS and TLS policy

This section is specific to `DirectMXTransport` — `RelayTransport` and
`LocalMTATransport` don't do MX resolution, so MTA-STS (which is about
"which MX hosts are authorized for this domain, and is TLS mandatory")
doesn't apply to them.

**`DirectMXTLSPolicy`** controls what TLS `DirectMXTransport` attempts
against each resolved host:

- **`.opportunistic`** (the default): try `.startTLS` first, with full
  certificate verification. If that fails, retry the *same host* in
  plaintext: when the server doesn't advertise STARTTLS, answers it with
  an error such as `454`, the handshake fails, or the certificate doesn't
  verify (`SMTPError.tlsCertificateInvalid`). Someone able to break TLS on
  the path could force plaintext anyway by stripping STARTTLS, so this
  costs nothing and keeps mail flowing to the many MX hosts with
  self-signed certificates. There is **no** plaintext retry after detected
  STARTTLS injection (`.starttlsInjection`) or with the host's circuit
  breaker open (it might have opened because of injections); delivery
  moves on to the next MX host instead.
- **`.fixed(TLSMode)`**: every host gets exactly the `TLSMode` you specify,
  uniformly, with no opportunistic fallback (`.fixed(.startTLS)` is how to
  require TLS for every host) and (crucially) **no MTA-STS
  involvement at all**, even for a domain that publishes an `enforce`
  policy. This is the explicit escape hatch for full manual control.

**MTA-STS (RFC 8461)** layers on top of whichever `tlsPolicy` you chose,
but only when you configure a policy provider:

```swift
let dnsResolver = DNSResolver(group: group)
let policyManager = MTASTSPolicyManager(dnsResolver: dnsResolver, addressResolver: dnsResolver)
let transport = DirectMXTransport(
    resolver: dnsResolver,
    config: DirectMXConfig(tlsPolicy: .opportunistic),
    group: group,
    mtaSTSPolicyProvider: policyManager
)
```

Leaving `mtaSTSPolicyProvider` as its default `nil` means MTA-STS is never
consulted at all — no DNS TXT lookup, no HTTPS fetch, purely additive
opt-in. When you do configure one, `MTASTSPolicyManager` discovers
(`_mta-sts.<domain>` TXT record), fetches
(`https://mta-sts.<domain>/.well-known/mta-sts.txt`), parses, and caches a
policy per domain (in-memory only — nothing here persists across process
restarts), and `DirectMXTransport` applies it automatically:

- **`mode: enforce`** — only MX hosts matching the policy's `mx:` patterns
  are ever dialed, mandatory STARTTLS only, and the certificate must carry
  a DNS subjectAltName for the MX host (an IP-address SAN alone isn't
  accepted). If none match, or every matching host fails, nothing is
  delivered now: the recipients get a temporary `451 4.7.5` and are queued
  for retry (RFC 8461 §5), never a fallback to a non-matching host or to
  plaintext.
- **`mode: testing`** — the same policy-matched, mandatory-TLS,
  DNS-name-checked attempt runs first, but a failure never blocks delivery: it falls through to the
  ordinary opportunistic path across all resolved hosts (RFC 8461 §5 —
  testing mode must never block delivery).
- **No policy for the domain, or `mode: none`** — identical to not having
  configured a provider at all: plain opportunistic delivery per
  `tlsPolicy`.

The policy fetch is bounded as a whole: `URLSessionMTASTSFetcher` (the
default `httpFetcher`) gives up after `timeout` seconds (default 60) from
connect to the last body byte and throws `MTASTSHTTPFetchError.timedOut`,
so a slow policy host can't hold up delivery to its domain indefinitely.
Redirects are never followed (RFC 8461 §3.3).

MTA-STS's SSRF-safety story mirrors `allowPrivateAddresses` above: the
HTTPS policy-file fetch target is address-checked the same way when you
pass `addressResolver` to `MTASTSPolicyManager.init` (as in the example
above), since the fetch hostname (`mta-sts.<domain>`) is just as
attacker-influenceable as an MX record when the recipient domain isn't
fully trusted.

DANE/TLSA is explicitly out of scope for this rewrite (deferred per the
plan) — MTA-STS is the only policy mechanism implemented.

## Sending in bulk / list-server use

`SMTPMailer` has two batch-oriented overloads on top of the single-message
`send`, both using the same bounded-concurrency sliding window
(`Configuration.maxInFlightBatchSends`, default 16): prime that many
concurrent sends, then start one more each time one finishes — never
launch every message's send eagerly regardless of capacity.

**Array-based batch send** — for a batch you already have fully in memory:

```swift
let results = await mailer.send(messages, envelopeFrom: .address("bounce@example.com"))
```

Note this overload does not `throw` — a single message's transport-level
failure (a connection error, a compose/DKIM failure) becomes a `.failed`
`DeliveryResult` for that message's own recipients rather than aborting
the whole batch and discarding every other message's results.

**Streaming batch send** — for a list server generating messages from a
subscriber database (or any other source too large to materialize as
`[EmailMessage]` up front):

```swift
struct SubscriberMessages: AsyncSequence, Sendable {
    typealias Element = EmailMessage
    struct AsyncIterator: AsyncIteratorProtocol {
        var subscribers: DatabaseCursor
        mutating func next() async throws -> EmailMessage? {
            guard let subscriber = try await subscribers.next() else { return nil }
            var message = EmailMessage(from: EmailAddress(address: "news@example.com"))
            message.to = [EmailAddress(address: subscriber.email)]
            message.subject = "This week's newsletter"
            message.textBody = renderNewsletter(for: subscriber)
            return message
        }
    }
    func makeAsyncIterator() -> AsyncIterator { AsyncIterator(subscribers: openCursor()) }
}

let stream = mailer.send(SubscriberMessages(), envelopeFrom: .address("bounce@example.com"))
for try await result in stream {
    print(result.recipient, result.outcome)
}
```

This overload provides genuine backpressure in both directions: it only
ever pulls the next message from your `AsyncSequence` when a currently
in-flight send actually finishes (never eagerly), and if your consumer
loop stops reading the returned stream (a slow consumer, or one that
breaks out early), the whole pipeline stalls rather than silently dropping
results or buffering unboundedly in memory. The returned
`AsyncThrowingStream` only throws for a genuinely stream-level failure —
your own `AsyncSequence`'s `next()` throwing — never for an individual
message's delivery outcome, which always comes through as a
`DeliveryResult`, exactly like the array-based overload.

## Deliverability headers

```swift
message.listUnsubscribe = ListUnsubscribe(
    mailto: "unsubscribe@example.com",
    url: "https://example.com/unsubscribe?id=abc123",
    postOneClick: true
)
message.precedence = .bulk
message.autoSubmitted = .autoGenerated
```

**`List-Unsubscribe`/`List-Unsubscribe-Post`** (RFC 8058) are no longer
optional for bulk mail: Gmail and Yahoo have required them from bulk
senders since February 2024.
`ListUnsubscribe.url`, if set, **must be `https://`** — RFC 8058 §3.1
requires it, and `MIMEComposer` enforces this unconditionally (not just
when `postOneClick` is set), throwing
`ComposerError.listUnsubscribeURLMustBeHTTPS` rather than silently
accepting or downgrading a non-HTTPS value. Setting `postOneClick: true`
without a `url` also throws (`postOneClickRequiresURL`) — the one-click
mechanism is specifically for the HTTPS POST target, so there's nothing
for the header to describe without one. If you configure DKIM signing too,
these headers are automatically covered by the signature (see
[DKIM signing](#dkim-signing)) — required for Gmail/Yahoo to actually honor
the one-click affordance per RFC 8058 §4.

**`Precedence`** (`.bulk`/`.list`/`.junk`) and **`Auto-Submitted`**
(`.autoGenerated`/`.autoReplied`/`.autoNotified`) are informal,
conventionally-paired headers (RFC 3834-adjacent, not all formally defined
by RFC 3834 itself) used for automated-mail loop suppression — e.g. so a
receiver's out-of-office responder doesn't reply back to your newsletter.
Set these on any automated or bulk mail; there's no cost to setting them
and real deliverability/interop benefit.

## Handling delivery results and retries

Every `DeliveryResult.Outcome` case, in plain language:

- **`.delivered(SMTPReply)`** — the receiving server accepted the message
  (a 2yz reply). Done.
- **`.queuedForRetry(nextAttempt:attempt:last:)`** — a transient failure
  (4yz other than 421, or 421/450/451/452 specifically — greylisting and
  "service unavailable, closing the channel" are classified and backed off
  differently from an ordinary 4yz). This means "try again later," not
  "give up."
- **`.permanentlyFailed(SMTPReply)`** — a 5yz reply. RFC 5321 says don't
  retry a permanent rejection; this library doesn't either.
- **`.expired(attempts:last:)`** — the retry ceiling was reached: this
  destination kept saying "try again later" until the configured
  max-attempt/expiry window ran out. Distinct from `.permanentlyFailed` so
  you can tell "the destination actively rejected this" apart from
  "we gave up retrying a destination that never said no, just not-yet."
- **`.ambiguous(SMTPReply?)`** — the connection failed *after* the `354`
  DATA-start reply but *before* the final `250` — the point of no return
  where the message may or may not have actually been accepted. This is
  never auto-retried (retrying here risks double delivery); surfaced so
  you can decide what's appropriate for your application (log it,
  alert on it, leave it for manual review).
- **`.failed(any Error & Sendable)`** — a failure with no `SMTPReply` that
  retrying won't fix: a DKIM/compose failure, an invalid address, a host
  name that doesn't exist, addresses filtered as private, or (for the
  batch `send` overloads specifically) one message's own thrown failure,
  mapped to this case per its would-be recipients so it doesn't take down
  the rest of the batch. `RelayTransport` and `LocalMTATransport` also
  report connection errors this way; `DirectMXTransport` classifies those
  as temporary (below).

**Automatic retry is a `DirectMXTransport`-only feature.** Every transport
classifies replies into these outcomes the same way (via the shared
`RetryBackoffPolicy`), so `RelayTransport` and `LocalMTATransport` can and
do return `.queuedForRetry` results — but nothing in those two transports
automatically re-attempts a queued send. If you're using `RelayTransport`
or `LocalMTATransport` and want retry behavior, you need to build it
yourself (re-call `mailer.send` for the `.queuedForRetry` recipients after
`nextAttempt`, with your own scheduling).

`DirectMXTransport`, by contrast, owns a `DirectMXRetryQueue` actor: any
`.queuedForRetry` result from a `send` call is automatically enqueued and
redelivered in the background on the classified backoff schedule, up to
that queue's configured expiry/attempt ceiling (at which point the
recipient's final outcome becomes `.expired`, not silently dropped).

Following RFC 5321 §4.5.4.1, `DirectMXTransport` treats failing to reach a
domain as temporary: refused or reset connections, connect and reply
timeouts, a peer hanging up, an open circuit breaker, TLS failures,
DNS timeouts or SERVFAIL, and MTA-STS `enforce` violations all become
`.queuedForRetry` (a synthesized `451 4.4.1` or `451 4.7.5` reply carries
the cause). A host name that doesn't exist (NXDOMAIN), a null MX, and 5yz
replies are final.

**The retry queue lives in memory only.** Pending retries are lost when the
process exits; if you need durability, record `.queuedForRetry` results
yourself (or deliver through a local MTA with its own spool). If you
want visibility into a background retry's eventual outcome, pass
`onTerminalRetryOutcome` to `DirectMXTransport`'s initializer; you can also
inspect what's still pending via `pendingRetryEntries()`.

## Testing your integration

`swift test` runs the full suite (about 400 tests) with zero external
dependencies and zero environment variables — including tests that
exercise a real STARTTLS handshake, a full `DirectMXTransport` delivery,
the DNS resolver and the MTA-STS fetcher against in-process fake servers
bound to `127.0.0.1`. None of it needs the internet or DNS: the 6.0.0
release checks ran it in Linux containers with no network beyond loopback,
and CI's `linux-offline` job does the same on every push.

**There is no built-in live-integration test tier against a real SMTP
server**, despite one being described in the original rewrite plan
(`Documentation/swift6-nio-rewrite-plan.md` §4.1/§5: an `SMTP_TESTS=1`-
gated CI job against a MailHog/smtp4dev service container). That tier was
never implemented — there's no `SMTP_TESTS` (or similarly-named) reference
anywhere in `Tests/`, and no test is opt-in. If you want to verify your own
integration against a real (or realistic fake) SMTP server, the
straightforward approach is to run
[MailHog](https://github.com/mailhog/MailHog) or
[smtp4dev](https://github.com/rnwood/smtp4dev) locally and point a
`RelayTransport` at it:

```swift
let transport = RelayTransport(
    config: RelayConfig(host: "127.0.0.1", port: 1025, tls: .none),
    group: group
)
```

then inspect what arrived via MailHog/smtp4dev's own web UI or API. There
is no publicly-exposed test double for `SMTPTransport` in this library
beyond `SMTPTransport` itself being a plain protocol — write your own fake
conforming to it (as this library's own test suite does internally) if you
want to unit-test code that calls `SMTPMailer` without any real I/O at
all.

## Migrating from the old Perfect-SMTP

If you used the pre-rewrite Perfect-SMTP, the old `EMail`/`SMTPClient`/
`Recipient` types are gone entirely. This is a ground-up replacement, not
a drop-in upgrade — there is no compatibility shim, and the public API
surface (`EmailMessage`, `EmailAddress`, `SMTPEnvelope`, `SMTPMailer`,
`SMTPTransport`) shares no types with the old one.

This wasn't a stylistic decision — the old implementation had two real,
structural bugs that made a compatible patch impractical:

1. **Bcc header leak.** Bcc addresses were correctly placed in the SMTP
   envelope (`RCPT TO`), but a `Bcc:` **header** was also written into the
   message body sent to *every* recipient — defeating the entire purpose
   of Bcc. The fix here isn't a conditional check; it's structural:
   `EmailMessage` has no `bcc` field at all, so there is nothing for a Bcc
   address to leak from. Bcc only ever exists as extra `SMTPEnvelope`
   recipients, supplied via `SMTPMailer.send`'s `bcc:` parameter.
2. **Fake quoted-printable subject encoding.** A fallback path emitted
   `Subject: =?utf-8?Q?<raw unescaped subject>?=` — labeled
   quoted-printable but never actually QP-encoded, corrupting any subject
   with non-ASCII or special characters that hit that branch. The new
   header encoder does real RFC 2047 encoding.

Beyond those two fixes, the old implementation wrapped `libcurl` via
`Perfect-CURL` for a single, blocking, synchronous `send()` call with no
STARTTLS control of its own, no AUTH mechanism control, no connection
pooling, no retry logic, and no DKIM signing. None of that carries over —
this is a from-scratch async/await SwiftNIO client, and porting old code
means rewriting your integration against the new types described
throughout this guide, not adjusting call sites.

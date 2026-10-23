# Perfect - SMTP [简体中文](README.zh_CN.md)

<p align="center">
    <a href="https://www.swift.org/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-6.2%2B-orange.svg?style=flat" alt="Swift 6.2+">
    </a>
    <a href="https://www.swift.org/platform-support/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B%20%7C%20Linux-lightgray.svg?style=flat" alt="Platforms macOS 12+ | Linux">
    </a>
    <a href="LICENSE" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0">
    </a>
</p>

Perfect-SMTP is a from-scratch Swift 6 / SwiftNIO SMTP client. It is not a
wrapper around libcurl or any other mail library — it drives the SMTP wire
protocol itself, including its own STARTTLS state machine, connection
pooling, DKIM signing, and MTA-STS policy enforcement.

It ships three delivery strategies (relay through an existing SMTP host,
hand off to a local MTA like Postfix/sendmail, or resolve MX records and
deliver directly), so you can pick the one that matches how you already
operate mail, or let Perfect-SMTP be the terminal MTA itself.

> 6.0.0 is a complete rewrite of the libcurl-based Perfect-SMTP 5.x. It is
> not a drop-in upgrade; see [Migrating from 5.x](#migrating-from-5x). The
> old code is preserved on the [`legacy`](../../tree/legacy) branch and the
> `5.0.0` tag.

This package is domain-agnostic by design — it has no Lasso-specific code
and no Lasso dependency. It is, however, a **core dependency** of
[Perfect-Lasso](https://github.com/taplin/Perfect-Lasso) — a Swift
reimplementation of the Lasso language, still in active development —
which uses it to implement its `email_send` tag.

## Features

- **Hand-rolled SMTP client on SwiftNIO** — its own STARTTLS upgrade
  sequence with byte-precise buffer discipline against injection/downgrade
  attacks, connection pooling with circuit breaking, and PIPELINING support.
- **DKIM signing** (RFC 6376) — RSA-SHA256 and Ed25519-SHA256 (RFC 8463),
  including dual-signing, with automatic oversigning of security-sensitive
  headers and a DMARC-alignment lint.
- **Three delivery strategies** — `RelayTransport` (an ESP or existing SMTP
  relay), `LocalMTATransport` (hand off to `sendmail`/Postfix on the same
  host), and `DirectMXTransport` (resolve MX records and deliver directly,
  with its own retry queue and circuit breaker).
- **MTA-STS** (RFC 8461) policy discovery, caching, and enforcement for
  direct-MX delivery, plus opportunistic STARTTLS by default.
- **SASL authentication** — `PLAIN`, `LOGIN`, and `XOAUTH2` (required by
  Gmail/Workspace, increasingly required by Microsoft 365).
- **Deliverability headers** — `List-Unsubscribe`/`List-Unsubscribe-Post`
  (RFC 8058), `Precedence`, `Auto-Submitted` — the headers Gmail and Yahoo
  have required for bulk senders since November 2025.
- **Bulk/list-server ready** — a bounded-concurrency batch `send` and an
  `AsyncSequence`-based streaming `send` for sending to millions of
  recipients without materializing them all in memory.
- **Structured delivery results** — every send returns a per-recipient
  outcome (delivered, queued for retry, permanently failed, expired,
  ambiguous, or a transport-level failure) instead of a single pass/fail.

For anything beyond the basics below, see the
**[full user guide](Documentation/user-guide.md)**.

## Requirements

- Swift 6.2 or later (`swift-tools-version: 6.2`, Swift 6 language mode)
- macOS 12 or later, or Linux (CI covers Ubuntu 24.04 with Swift 6.2 and 6.4)

iOS, tvOS and watchOS are not supported: this is a server-side package
(SwiftNIO sockets, and `LocalMTATransport` launches a local `sendmail`).

Dependencies are all Apple/SSWG packages: `swift-nio`, `swift-nio-ssl`,
`swift-log` and `swift-crypto` (the last for DKIM; its version range is
`3.4.0..<5.0.0`, so it resolves alongside packages on either swift-crypto
major).

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "6.0.0")
```

It has two products:

| Product | Contents |
|---|---|
| `PerfectSMTP` | Everything: the transports (`RelayTransport`, `LocalMTATransport`, `DirectMXTransport`), `SMTPMailer`, the connection pool, the DNS resolver and MTA-STS. Re-exports `PerfectSMTPCore`. |
| `PerfectSMTPCore` | Message model, MIME composer, header/body encoders and the DKIM signer, with no networking. Depend on it directly only if you compose or sign messages without sending them. |

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "PerfectSMTP", package: "Perfect-SMTP"),
    ]
)
```

## Quick start

Send one email through an existing SMTP relay (a corporate MTA or an ESP
like SendGrid/Postmark/SES):

```swift
import NIOPosix
import PerfectSMTP

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

let transport = RelayTransport(
    config: RelayConfig(
        host: "smtp.example.com",
        port: 587,
        tls: .startTLS,
        auth: .plain(username: "postmaster@example.com", password: "secret")
    ),
    group: group
)
let mailer = SMTPMailer(transport: transport)

var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
message.to = [EmailAddress(address: "user@dest.com")]
message.subject = "Hello from Perfect-SMTP"
message.textBody = "Hi there!"

let results = try await mailer.send(message, envelopeFrom: .address("ops@example.com"))
for result in results {
    print(result.recipient, result.outcome)
}

await transport.shutdown()
try await group.shutdownGracefully()
```

`MultiThreadedEventLoopGroup` comes from SwiftNIO's `NIOPosix`, which
PerfectSMTP already depends on; if your build requires every imported module
to be a declared dependency, add
`.package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0")` and
`.product(name: "NIOPosix", package: "swift-nio")`.

That's it for the basic case. For DKIM signing, direct-MX delivery,
authentication options, bulk sending, and deliverability headers, see the
**[user guide](Documentation/user-guide.md)**.

## Security defaults

You get these without configuring anything:

- **TLS certificates are verified.** Every TLS connection (`.startTLS`,
  `.implicit`, and `DirectMXTransport`'s STARTTLS attempts) uses
  `TLSConfiguration.makeClientConfiguration()`: full chain and hostname
  verification.
- **`.startTLS` never downgrades.** If the server doesn't advertise
  `STARTTLS`, the connection fails with `SMTPError.starttlsRequired`
  instead of continuing in plaintext. Bytes injected around the upgrade
  (the CVE-2026-41319 class) fail the connection with
  `.starttlsInjection`.
- **No AUTH in cleartext.** A `RelayConfig` with credentials and
  `tls: .none` throws `RelayTransportError.authenticationRequiresTLS`
  before dialing. Set `allowsAuthenticationWithoutTLS: true` only for a
  relay you trust, such as a loopback MTA or a test server.
- **No header or command injection.** Addresses, the EHLO hostname, extra
  headers, message IDs, content types and content IDs are rejected if they
  contain CR, LF or other control characters; subjects and display names
  have them stripped and are RFC 2047-encoded. The DATA payload is
  dot-stuffed. Bcc addresses only ever go into `RCPT TO`, never a header.
- **Every network step has a timeout:** TCP connect (30 s), each SMTP reply
  including the greeting, EHLO, STARTTLS and the TLS handshake (300 s), the
  final reply after DATA (600 s), each DNS query (5 s), the MTA-STS policy
  fetch (60 s), and the `sendmail` process (60 s). All are configurable.
- **No secrets in logs.** The library logs only the DKIM alignment warning
  and MTA-STS decisions (domains, hosts, errors), never message bodies or
  credentials. `RelayConfig.Auth`, `SASLPlain`, `SASLLogin` and
  `SigningKey` print redacted descriptions.
- **Direct MX delivery** refuses private, loopback and link-local
  addresses unless `allowPrivateAddresses` is set, uses opportunistic
  STARTTLS that falls back to plaintext only when a server doesn't offer
  STARTTLS (never after a failed handshake), and honors MTA-STS `enforce`
  policies when you configure a policy provider.

## Migrating from 5.x

5.x wrapped libcurl through Perfect-CURL: you built an `SMTPClient` with a
URL and credentials, filled in an `EMail`, and called a blocking
`send(completion:)`. 6.0.0 shares no types with it, so a port is a rewrite
of the call site, not a find-and-replace:

| 5.x | 6.0.0 |
|---|---|
| `SMTPClient(url: "smtp://host", username:, password:)` | `RelayTransport(config: RelayConfig(host:port:tls:auth:), group:)` |
| `smtps://` URL | `tls: .implicit` (port 465); `tls: .startTLS` for port 587 |
| `Recipient(name:address:)` | `EmailAddress(displayName:address:)` |
| `EMail(client:)` | `EmailMessage(from:)`, sent with `SMTPMailer(transport:).send(_:envelopeFrom:)` |
| `email.content` / `.html` / `.text` | `message.htmlBody` / `message.textBody` (set both for multipart/alternative) |
| `email.bcc` | the `bcc:` parameter of `send` (never written to a header) |
| `email.attachments` (file paths) | `message.attachments` (`Attachment(filename:contentType:data:)`) |
| `try email.send { code, header, body in }` | `let results = try await mailer.send(...)`, one `DeliveryResult` per recipient |

What changes in behavior: sending is `async`; the envelope sender is
explicit (`envelopeFrom: .address(...)` or `.null`); STARTTLS is mandatory
when requested; credentials over a plaintext connection are refused (see
above); and the 5.x bugs that wrote a `Bcc:` header to every recipient and
emitted a mislabeled quoted-printable subject are gone. There is no libcurl
or OpenSSL system dependency any more, so the old `libssl-dev`/`libcurl`
install notes no longer apply.

The [user guide](Documentation/user-guide.md#migrating-from-the-old-perfect-smtp)
explains why this is a rewrite rather than an update.

## Testing

```
swift test
```

The whole suite is hermetic: no environment variables, no internet, no DNS
and no external mail server. Tests that need sockets (a real STARTTLS
handshake, a full DirectMX delivery, the DNS resolver, the MTA-STS
fetcher) run against in-process fake servers on `127.0.0.1`. CI runs it on
Linux and macOS in debug and release with `-warnings-as-errors`.

There is no live-integration tier. To check your own setup against a real
SMTP server, point a `RelayTransport` at a local
[MailHog](https://github.com/mailhog/MailHog) or
[smtp4dev](https://github.com/rnwood/smtp4dev) instance; see
[Testing your integration](Documentation/user-guide.md#testing-your-integration).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

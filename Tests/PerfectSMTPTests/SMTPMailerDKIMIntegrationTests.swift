//
//  SMTPMailerDKIMIntegrationTests.swift
//  PerfectSMTPTests
//
//  Confirms the seam Phase 1 built (`SMTPMailer(transport:signer:)`,
//  `signer: (any MessageSigner)? = nil`) now works end-to-end with a real
//  signer for the first time (plan §4.6/§9's Phase 2 scope: "You likely
//  don't need to change SMTPMailer.swift much since Phase 1 already built
//  this seam correctly -- verify, don't redesign"). Also exercises the
//  DMARC-alignment-lint logging path this phase adds to `SMTPMailer`.
//

import Foundation
import Logging
import Testing
@testable import PerfectSMTP

struct SMTPMailerDKIMIntegrationTests {

    private static let rsa2048PEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAwYYqnvIW69nFbGXs/1MlUxvZ6omQwRUQG4vXQvOsScGMPXXR
    ZiYhxblhM3IB+qJ1/x21yT0h0NaFSWMPE2uKxlG8+PPlYEdo7J0RdzX6zPP9AEz9
    eJGl0qEo2hIdHI/rXe5ROXFeG4c/cl4i3I1nDWlcS/g+A6dGtWbtCONlYnGXE5wS
    B6oVuJxOvKMlC0x1HuxQxeJ1K8gHfLg4LT4At4eNI8tuNMDPCLUbqmKvrmOO0SDO
    FD26mxiVoRHQxVX+Fm8xi4f2j2x1H2/rY+dpr8chepCCXGnqHA1GqYuq5zhgfx+o
    SGQgk1UJibN+ffvFxfXeVJIcrLaWYUe81XJg6wIDAQABAoIBAHKB6pIl+L4RGynq
    nXLuRbWJU0XdpBM7XU6PTg3FlPoHVe2/2ukwQud1qzf/i4A7xMnxUHEEhQ/G/xLP
    VEpPZcu27bP4zI5Ncp4eygjZnc7Lx7X32DsRIycgSMXP1f3igogPzWvJ0r9DJZ2M
    aeBKouFiqEQjXL5YqhQIFNUfiAvY1vvzz/xxV7bUQo1S7gmLKI6LGqbNiFTHo/sK
    RiRjO2G6/8G6R4pzOkE2rf1/gqckI/wVBCdaSeTym/tTw3/oFEgdA2qhwPisPhPv
    0BI30eJDtAhBuhUgXhVr5RZVYF84DcZPGQZq/l6mEvclDGJR6WisaAFqnq7fu0P0
    Pq2lB8ECgYEA4Gh+XDXngVVspP3LKg6p0udqW6C5IbjN0RUIHfhQhH6Lu3zrTFpX
    VZqd+aYciKD9HPxov+7YSMUjCFaDsJjqg75TRZuHbLVJkONhdiaOO0PU7588wNHm
    pwh/vneV5w6bqtiJCxOfH3FzH2CC5G5RQ2FBLBixZqoc5hQQLMKkqBsCgYEA3MSi
    BYNgSvL/VGN0EyVYuHdqBnSUFLRmdj0hvGR6JGaShoh7K8Oaz4a4v06jf9PUCdA5
    JJpBnZ+IFwQTyoMkbesleIQcFVRg0tTVU7PxEng2+Beg5qnNPuRuIYz7HvVn5xuu
    5kN2+wWEyz5oVhguJg7zg2p7RNWS+v7AsFEZV3ECgYEAofgJq/hkHZ9QiU19A+AN
    huHsjDHXLZW7R7uMXkVJqDfGFw60rilOe8TbXMMeOScpSXCNEmsLxIo1HOGEr0PP
    kEMgy07UUgwPCvpy79ooMnJlEIa4TNuzRMAHo6ugkGKkzIz5bPs+kG1MEEuSbdmJ
    4b4iUfeIo3cI4K9+dTAPtB0CgYBQeBvWhpyCtS/8QoP8tpAwLNaoo7WWFmuCjaXO
    VZFv0zN1dinvOc0j96c/lBpkbYHMUemCPffMzGl+ei38kvCkYCG4W+8glzDzqEBZ
    0iz83nSq2XH8ocf+NKUv9YNTNYA57Q1DQTQNK2XL72N4fjfUB38bV6S24mJAurrh
    ia4DAQKBgQDOmIn9iyXgGFMbldehPMU9RGKyJCMG47lBIaG9lg63SNLByJTdcn96
    6kNXD9cRbEEz86ebdtmC/4knKOSyN6ymPv7z5UPVvN8ezpNQiQ0ixS5AkTL3yYKv
    Qjb87l8lMbWyR5WKYbWVpsTPiEmw7iU4GptR5DXAbhzOBWY5VEo0WQ==
    -----END RSA PRIVATE KEY-----
    """

    @Test func mailerConfiguredWithADKIMSignerProducesASignedMessageContainingADKIMSignatureHeader() async throws {
        let capture = CapturingTransport()
        let signer = try DKIMSigner(
            domain: "example.com",
            selector: "s1",
            signedHeaders: ["from", "to", "subject"],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        let mailer = SMTPMailer(transport: capture, signer: signer)

        var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Hello"
        message.textBody = "hi there"

        let results = try await mailer.send(message, envelopeFrom: .address("bounce@example.com"))

        #expect(results.count == 1)
        let sent = try #require(await capture.lastMessage)
        let serialized = String(decoding: sent.rfc5322, as: UTF8.self)

        // The signature must be present, at the very top of the message
        // (§3.5: "SHOULD be prepended"), and precede the CRLFCRLF
        // header/body boundary -- i.e. it's a real header, not something
        // accidentally serialized into the body.
        #expect(serialized.hasPrefix("DKIM-Signature: v=1; a=rsa-sha256;"))
        let headerBlock = try #require(serialized.components(separatedBy: "\r\n\r\n").first)
        #expect(headerBlock.contains("DKIM-Signature:"))
        #expect(headerBlock.contains("d=example.com"))
        #expect(headerBlock.contains("s=s1"))
    }

    // Milestone review finding (LassoPerfectSMTP Phase F, protocol pass):
    // `signedHeaders` is fixed at signer-construction time, so a signer
    // built with an empty (or otherwise fixed) base set -- relying purely
    // on `DKIMSigner.alwaysOversignedHeaders` -- previously gave a
    // message's `extraHeaders` (Lasso's `-extraMIMEHeaders`) zero DKIM
    // coverage: they're present in the composed message but absent from
    // `h=`, so an on-path party could tamper with a custom header
    // without invalidating the signature. `SMTPMailer.composeAndSign`
    // now widens the signer's `signedHeaders` with the message's own
    // `extraHeaders` names (`DKIMSigner.signingAdditionalHeaders`) right
    // before signing -- this proves that actually happens end-to-end.
    @Test func messageWithExtraMIMEHeadersGetsThemCoveredByTheDKIMSignaturesHTag() async throws {
        let capture = CapturingTransport()
        let signer = try DKIMSigner(
            domain: "example.com",
            selector: "s1",
            signedHeaders: [],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        let mailer = SMTPMailer(transport: capture, signer: signer)

        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Hello"
        message.textBody = "hi there"
        message.extraHeaders = [("X-Campaign-ID", "spring-sale-42")]

        _ = try await mailer.send(message, envelopeFrom: .address("bounce@example.com"))

        let sent = try #require(await capture.lastMessage)
        let serialized = String(decoding: sent.rfc5322, as: UTF8.self)
        let headerBlock = try #require(serialized.components(separatedBy: "\r\n\r\n").first)

        // The custom header must actually be present in the composed
        // message (sanity check that this test exercises a real gap, not
        // a no-op)...
        #expect(headerBlock.contains("X-Campaign-ID: spring-sale-42"))
        // ...and the DKIM-Signature's own `h=` tag must list its name,
        // proving it's actually covered by the signature, not just
        // present alongside it.
        let dkimLine = try #require(headerBlock.components(separatedBy: "\r\n").first { $0.hasPrefix("DKIM-Signature:") })
        let hTag = try #require(dkimLine.components(separatedBy: "; ").first { $0.hasPrefix("h=") })
        let signedNames = hTag.dropFirst("h=".count).split(separator: ":").map { $0.lowercased() }
        #expect(signedNames.contains("x-campaign-id"))
    }

    @Test func mailerWithoutASignerStillSendsUnsignedExactlyAsInPhase1() async throws {
        let capture = CapturingTransport()
        let mailer = SMTPMailer(transport: capture)

        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hi"

        _ = try await mailer.send(message, envelopeFrom: .address("bounce@example.com"))

        let sent = try #require(await capture.lastMessage)
        #expect(!String(decoding: sent.rfc5322, as: UTF8.self).contains("DKIM-Signature"))
    }

    @Test func misalignedDKIMDomainLogsAWarningButStillSendsSuccessfully() async throws {
        let capture = CapturingTransport()
        let (logHandler, logHandlerFactory) = makeCapturingLogHandler(CapturingLogHandlerMaker.self)
        var logger = Logger(label: "test.dkim.alignment", factory: logHandlerFactory)
        logger.logLevel = .trace
        let signer = try DKIMSigner(
            domain: "third-party-esp.example",
            selector: "s1",
            signedHeaders: ["from"],
            keys: [try SigningKey.rsa(pem: Self.rsa2048PEM)]
        )
        let mailer = SMTPMailer(transport: capture, signer: signer, logger: logger)

        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hi"

        // d= ("third-party-esp.example") does not DMARC-align with the
        // From domain ("example.com") -- this must produce a logged
        // warning, and must NOT prevent the send from completing.
        let results = try await mailer.send(message, envelopeFrom: .address("bounce@example.com"))

        #expect(!results.isEmpty)
        #expect(logHandler.warnings.contains { $0.contains("DMARC-align") })
    }
}

private actor CapturingTransport: SMTPTransport {
    private(set) var lastMessage: SignedMessage?

    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        lastMessage = message
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"])))
        }
    }
}

/// A minimal `LogHandler` that just records warning-level messages, so the
/// DMARC-alignment lint test can assert a warning was actually emitted
/// without depending on any particular logging backend's output format.
/// `LogHandler.log(...)` is a synchronous protocol requirement, so this
/// deliberately uses a lock-protected class (mirroring
/// `PerfectSMTPCoreTests/TestHelpers.swift`'s `SequentialBoundaries`
/// pattern) rather than an actor -- an actor would require hopping into an
/// unstructured `Task` from inside `log`, which is not guaranteed to have
/// completed by the time this same-thread test reads `warnings` back out.
private final class CapturingLogHandlerStorage: @unchecked Sendable {
    private let lock = NSLock()
    private var _warnings: [String] = []

    var warnings: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _warnings
    }

    func record(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        _warnings.append(message)
    }
}

///
/// swift-log 1.11 added `LogHandler.log(event:)` and deprecated the flat
/// `log(level:message:...)` requirement this handler implements, but the
/// package supports swift-log back to 1.5.0, which has no `LogEvent` type.
/// To build warning-free against both, the handler is marked deprecated
/// (which silences the "deprecated default implementation" diagnostic on
/// its conformance) and is only ever constructed through a protocol
/// requirement, so no call site names the deprecated type directly.
@available(*, deprecated, message: "Test-only; see the comment above.")
private struct CapturingLogHandler: LogHandler {
    let storage = CapturingLogHandlerStorage()
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    var warnings: [String] { storage.warnings }

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(
        level: Logger.Level, message: Logger.Message, metadata: Logger.Metadata?,
        source: String, file: String, function: String, line: UInt
    ) {
        guard level == .warning else { return }
        storage.record(message.description)
    }
}

private protocol CapturingLogHandlerMaking {
    static func make() -> (storage: CapturingLogHandlerStorage, factory: @Sendable (String) -> any LogHandler)
}

private enum CapturingLogHandlerMaker: CapturingLogHandlerMaking {
    @available(*, deprecated, message: "Test-only; see CapturingLogHandler.")
    static func make() -> (storage: CapturingLogHandlerStorage, factory: @Sendable (String) -> any LogHandler) {
        let handler = CapturingLogHandler()
        return (handler.storage, { _ in handler })
    }
}

private func makeCapturingLogHandler<Maker: CapturingLogHandlerMaking>(
    _ maker: Maker.Type
) -> (storage: CapturingLogHandlerStorage, factory: @Sendable (String) -> any LogHandler) {
    maker.make()
}

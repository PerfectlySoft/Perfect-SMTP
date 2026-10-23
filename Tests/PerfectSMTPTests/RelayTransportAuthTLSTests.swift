//
//  RelayTransportAuthTLSTests.swift
//  PerfectSMTPTests
//
//  `RelayTransport` refuses to authenticate over a plaintext (`tls: .none`)
//  connection unless `RelayConfig.allowsAuthenticationWithoutTLS` is set,
//  and `SMTPConnection` refuses an EHLO hostname that would inject a
//  command.
//

import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct RelayTransportAuthTLSTests {
    private struct DialReached: Error {}

    private actor DialCounter {
        private(set) var count = 0
        func increment() { count += 1 }
    }

    private func send(_ config: RelayConfig, dials: DialCounter) async throws -> [DeliveryResult] {
        let transport = RelayTransport(config: config, group: NIOAsyncTestingEventLoop()) { _ in
            await dials.increment()
            throw DialReached()
        }
        let envelope = try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["rcpt@relay.example"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))
        do {
            let results = try await transport.send(envelope, message)
            await transport.shutdown()
            return results
        } catch {
            await transport.shutdown()
            throw error
        }
    }

    @Test(arguments: [
        RelayConfig.Auth.plain(username: "u", password: "p"),
        .login(username: "u", password: "p"),
        .xoauth2(username: "u", tokenProvider: { "token" }),
    ])
    func authOverPlaintextIsRefusedBeforeDialing(auth: RelayConfig.Auth) async throws {
        let dials = DialCounter()
        let config = RelayConfig(host: "relay.example", port: 25, tls: .none, auth: auth)
        await #expect(throws: RelayTransportError.authenticationRequiresTLS) {
            _ = try await send(config, dials: dials)
        }
        #expect(await dials.count == 0, "credentials must not be offered to a plaintext connection")
    }

    @Test func authOverPlaintextIsAllowedWhenExplicitlyOptedIn() async throws {
        let dials = DialCounter()
        let config = RelayConfig(
            host: "127.0.0.1", port: 1025, tls: .none, auth: .plain(username: "u", password: "p"),
            allowsAuthenticationWithoutTLS: true
        )
        await #expect(throws: (any Error).self) { _ = try await send(config, dials: dials) }
        #expect(await dials.count >= 1)
    }

    @Test(arguments: [TLSMode.startTLS, .implicit])
    func authOverTLSIsNotAffected(tls: TLSMode) async throws {
        let dials = DialCounter()
        let config = RelayConfig(host: "relay.example", port: 587, tls: tls, auth: .plain(username: "u", password: "p"))
        await #expect(throws: (any Error).self) { _ = try await send(config, dials: dials) }
        #expect(await dials.count >= 1)
    }

    @Test func noAuthOverPlaintextIsNotAffected() async throws {
        let dials = DialCounter()
        let config = RelayConfig(host: "relay.example", port: 25, tls: .none)
        await #expect(throws: (any Error).self) { _ = try await send(config, dials: dials) }
        #expect(await dials.count >= 1)
    }

    @Test(arguments: ["client.example.com\r\nRSET", "client\nQUIT", "client\r"])
    func ehloHostnameWithCRLFIsRejectedBeforeAnythingIsWritten(hostname: String) async throws {
        let (connection, channel) = try await ConnectionHarness.make(ehloHostname: hostname)
        await #expect(throws: HeaderEncoder.HeaderInjectionError.controlCharacterInField("EHLO hostname")) {
            _ = try await connection.negotiateCapabilities()
        }
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
    }
}

struct CredentialRedactionTests {
    @Test func relayConfigAndSASLDescriptionsNeverContainThePassword() {
        let secret = "hunter2-SECRET"
        let config = RelayConfig(host: "relay.example", port: 587, tls: .startTLS, auth: .plain(username: "u", password: secret))
        let login = RelayConfig(host: "relay.example", port: 587, tls: .startTLS, auth: .login(username: "u", password: secret))
        let rendered = [
            "\(config)", String(reflecting: config), "\(login)", String(reflecting: login),
            "\(config.auth)", "\(SASLPlain(username: "u", password: secret))",
            String(reflecting: SASLLogin(username: "u", password: secret)),
        ]
        for text in rendered {
            #expect(!text.contains(secret), "\(text)")
        }
        #expect("\(config.auth)".contains("<redacted>"))
    }

    @Test func dumpAndMirrorNeverExposeThePasswordOrToken() {
        let secret = "S3CRET-PW"
        let values: [Any] = [
            RelayConfig(host: "h", port: 587, tls: .startTLS, auth: .plain(username: "u", password: secret)),
            RelayConfig(host: "h", port: 587, tls: .startTLS, auth: .login(username: "u", password: secret)),
            RelayConfig.Auth.plain(username: "u", password: secret),
            SASLPlain(username: "u", password: secret),
            SASLLogin(username: "u", password: secret),
            XOAuth2(username: "u") { secret },
        ]
        for value in values {
            var dumped = ""
            dump(value, to: &dumped)
            #expect(!dumped.contains(secret), "\(dumped)")
            let children = Mirror(reflecting: value).children.map { "\($0.label ?? ""): \($0.value)" }.joined()
            #expect(!children.contains(secret), "\(children)")
        }
    }
}

struct WireInjectionTests {
    @Test(arguments: ["client example.com", "client.example.com>", "-client", "client_example.com", "[1.2.3]"])
    func anEHLOHostnameThatIsNotAnLDHNameIsRejected(hostname: String) async throws {
        let (connection, channel) = try await ConnectionHarness.make(ehloHostname: hostname)
        await #expect(throws: (any Error).self) { _ = try await connection.negotiateCapabilities() }
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
    }

    /// `SMTPEnvelope.recipients` is mutable after its validating init, so
    /// the connection re-checks: the reviewer's `NOTIFY=`/`ORCPT=` payload
    /// must not reach the wire, and nothing (not even MAIL FROM) is sent.
    @Test func aRecipientMutatedAfterValidationIsRejectedBeforeAnythingIsWritten() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        var envelope = try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["ok@example.com"])
        envelope.recipients = ["victim@example.test> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;spoof@evil.test"]
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))
        await #expect(throws: (any Error).self) { _ = try await connection.sendMessage(envelope, message) }
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
    }
}

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

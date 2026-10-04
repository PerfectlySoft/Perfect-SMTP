//
//  LocalMTATransportTests.swift
//  PerfectSMTPTests
//
//  Plan §5: a test that a slow/large stderr writer doesn't deadlock the
//  stdin/stdout exchange -- the pipe-buffer-deadlock scenario the design
//  note calls out (a process that writes enough to one pipe's kernel
//  buffer while only the other is being drained blocks forever without
//  concurrent draining). The termination-handler-to-continuation
//  double-resume guard is documented as a code-review-level self-check in
//  `LocalMTATransport.swift` itself (a genuine concurrent race isn't
//  practical to construct without forking Foundation's `Process`).
//

import Foundation
import Testing
@testable import PerfectSMTP

struct LocalMTATransportTests {

    /// Writes a small, portable POSIX `sh` "fake MTA" script to a temp file
    /// and marks it executable. `stderrBytes` controls how much it writes
    /// to stderr before exiting -- large enough to exceed the OS pipe
    /// buffer (typically 64KiB) proves the deadlock scenario is real, not
    /// just theoretical. (`/bin/sh`, not Python: the `swift` Linux images
    /// ship without `python3`, which made these tests fail there with exit
    /// code 127 before the transport was ever exercised.)
    private func makeFakeMTA(stderrBytes: Int, exitCode: Int32 = 0) throws -> URL {
        let script = """
        #!/bin/sh
        cat > /dev/null
        head -c \(stderrBytes) /dev/zero | tr '\\000' E >&2
        head -c \(stderrBytes) /dev/zero | tr '\\000' O
        exit \(exitCode)
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-mta-\(UUID().uuidString).sh")
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    /// Writes a fake MTA that, instead of doing anything MTA-like, dumps
    /// its own received `argv` (everything after the script path) to a
    /// sibling file next to itself -- `<script path>.args`, each argument
    /// NUL-terminated (empty when there are no arguments) -- then exits 0. Used to structurally inspect the exact arguments
    /// `LocalMTATransport` constructs (FIX #2 layer 2's `"--"` separator,
    /// FIX #3's `.null` reverse-path `-f` argument) without needing any
    /// production-code seam to intercept `Process.arguments` directly.
    /// A sibling file (not an environment variable) is used deliberately:
    /// FIX #2's defense-in-depth `process.environment` lockdown means the
    /// subprocess no longer inherits arbitrary environment variables, so
    /// the sibling-file path is derived purely from the script's own `$0`,
    /// needing no environment cooperation at all.
    private func makeArgvCapturingMTA() throws -> URL {
        let script = """
        #!/bin/sh
        cat > /dev/null
        if [ "$#" -gt 0 ]; then printf '%s\\000' "$@"; fi > "$0.args"
        exit 0
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-mta-argv-\(UUID().uuidString).sh")
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    /// Reads back and splits the argv dump `makeArgvCapturingMTA`'s script
    /// wrote for a given script URL.
    private func capturedArguments(for scriptURL: URL) throws -> [String] {
        let data = try Data(contentsOf: URL(fileURLWithPath: scriptURL.path + ".args"))
        guard !data.isEmpty else { return [] }
        // Every argument (including an empty one, e.g. `-f ""`) ends in a
        // NUL, so the split's final element is always the empty remainder.
        return data.split(separator: 0x00, omittingEmptySubsequences: false)
            .dropLast()
            .map { String(decoding: $0, as: UTF8.self) }
    }

    // MARK: - FIX #2 layer 2 (security review, CWE-88, defense-in-depth)

    @Test func recipientsAreSeparatedFromPrecedingOptionsByADoubleDash() async throws {
        let scriptURL = try makeArgvCapturingMTA()
        defer {
            try? FileManager.default.removeItem(at: scriptURL)
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: scriptURL.path + ".args"))
        }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path))
        let envelope = try SMTPEnvelope(
            mailFrom: .address("from@example.com"),
            recipients: ["a@example.com", "b@example.com"]
        )
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        _ = try await transport.send(envelope, message)

        let arguments = try capturedArguments(for: scriptURL)
        guard let dashDashIndex = arguments.firstIndex(of: "--") else {
            Issue.record("expected a literal \"--\" end-of-options separator in \(arguments)")
            return
        }
        // Every recipient must appear strictly after "--", and nothing
        // that looks like a recipient may appear before it.
        let afterDashDash = arguments[(dashDashIndex + 1)...]
        #expect(Array(afterDashDash) == ["a@example.com", "b@example.com"])
        #expect(!arguments[..<dashDashIndex].contains("a@example.com"))
        #expect(!arguments[..<dashDashIndex].contains("b@example.com"))
    }

    // MARK: - FIX #3 (protocol correctness, milestone review): null
    // reverse-path's `-f` argument

    @Test func nullReversePathPassesEmptyStringNotWireAngleBracketsToDashF() async throws {
        let scriptURL = try makeArgvCapturingMTA()
        defer {
            try? FileManager.default.removeItem(at: scriptURL)
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: scriptURL.path + ".args"))
        }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path))
        let envelope = try SMTPEnvelope(mailFrom: .null, recipients: ["to@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        _ = try await transport.send(envelope, message)

        let arguments = try capturedArguments(for: scriptURL)
        guard let fIndex = arguments.firstIndex(of: "-f") else {
            Issue.record("expected a \"-f\" argument in \(arguments)")
            return
        }
        guard fIndex + 1 < arguments.count else {
            Issue.record("expected an argument following \"-f\" in \(arguments)")
            return
        }
        // The fix: an empty string, not the SMTP wire-syntax literal `<>`
        // (see `LocalMTATransport.runProcess`'s `.null` case for the full
        // research citation backing this choice).
        #expect(arguments[fIndex + 1] == "")
        #expect(arguments[fIndex + 1] != "<>")
    }

    /// Races `body` against a timeout, failing the test explicitly (rather
    /// than hanging the whole suite forever) if the deadlock scenario this
    /// test exists to catch were ever reintroduced.
    private func withDeadlockGuard<T: Sendable>(
        seconds: Double = 10,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
                throw DeadlockGuardError.timedOut
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    @Test func slowStderrWriterDoesNotDeadlockStdinStdoutExchange() async throws {
        // 4x a typical 64KiB pipe buffer, on both stdout AND stderr --
        // large enough that without concurrent draining of both, the
        // process blocks forever trying to write past the full kernel
        // buffer, which in turn blocks our stdin write/close, which in
        // turn means the process never sees EOF on stdin and never exits.
        let scriptURL = try makeFakeMTA(stderrBytes: 256 * 1024)
        defer { try? FileManager.default.removeItem(at: scriptURL) }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path, processTimeout: 15))
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["to@example.com"])
        // A non-trivial body so the stdin-write side also has real work to
        // do concurrently with the pipe-filling stdout/stderr writer.
        let body = Array(repeating: "X", count: 50_000).joined()
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\n\(body)".utf8))

        let results = try await withDeadlockGuard {
            try await transport.send(envelope, message)
        }

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected delivered, got \(results[0].outcome)")
            return
        }
    }

    @Test func nonZeroExitSurfacesStderrInTheThrownError() async throws {
        let scriptURL = try makeFakeMTA(stderrBytes: 100, exitCode: 1)
        defer { try? FileManager.default.removeItem(at: scriptURL) }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path))
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["to@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        await #expect(throws: LocalMTAError.self) {
            _ = try await withDeadlockGuard {
                try await transport.send(envelope, message)
            }
        }
    }
}

private enum DeadlockGuardError: Error {
    case timedOut
}

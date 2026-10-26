//
//  LocalMTATransport.swift
//  PerfectSMTP
//
//  Plan §3/§9 Phase 1: async-safe wrapper around `sendmail`/`postfix -t`
//  via `Foundation.Process`, for operators who already run a hardened MTA
//  on the same host. Delivery/retry/TLS from the point of handoff onward
//  is the local MTA's responsibility, not this library's — a
//  `DeliveryResult` from this transport reflects only "did the local MTA
//  accept the handoff," not per-recipient delivery.
//
//  Design notes called out explicitly by the plan, all addressed here:
//   - a single-resume guard bridging `Process.terminationHandler` to a
//     continuation (never resume twice);
//   - concurrent stdout/stderr draining to avoid a pipe-buffer deadlock (a
//     process that writes enough to stderr while only stdout is being
//     read, or vice versa, blocks forever without this);
//   - confinement behind an actor, since `Foundation.Process` is not
//     `Sendable`.
//

import Foundation

public struct LocalMTAConfig: Sendable {
    /// Path to the MTA binary. Defaults to `sendmail`'s conventional
    /// location; `/usr/sbin/sendmail` is itself frequently a symlink to
    /// Postfix/Exim/etc.'s sendmail-compatible shim, which is exactly the
    /// interface this transport targets (plan §3: "the same pattern PHP's
    /// `mail()` and countless other language runtimes use").
    public var executablePath: String
    /// Extra arguments before the recipient list. `-i` (don't treat a
    /// lone `.` as end-of-input -- irrelevant here since we pass the
    /// envelope via `-t`/args, not stdin-terminated-by-dot, but harmless
    /// and conventional) and `-t` (read recipients from the message
    /// headers) are common; `-t` is NOT passed by default here because
    /// this transport passes the envelope recipients explicitly as
    /// trailing arguments instead, which is the more precise, Bcc-safe
    /// interface (matches `SMTPEnvelope.recipients` being the sole source
    /// of truth for who receives the message, header content aside).
    public var extraArguments: [String]
    public var processTimeout: TimeInterval

    public init(
        executablePath: String = "/usr/sbin/sendmail",
        extraArguments: [String] = ["-i"],
        processTimeout: TimeInterval = 60
    ) {
        self.executablePath = executablePath
        self.extraArguments = extraArguments
        self.processTimeout = processTimeout
    }
}

public enum LocalMTAError: Error, Sendable, Equatable {
    case nonZeroExit(code: Int32, stderr: String)
    case processLaunchFailed(String)
    case timedOut
}

/// Confines `Foundation.Process` (not `Sendable`) behind an actor, per the
/// plan's explicit design note.
public actor LocalMTATransport: SMTPTransport {
    private let config: LocalMTAConfig

    public init(config: LocalMTAConfig = .init()) {
        self.config = config
    }

    /// Hands `message` to the configured local MTA binary via `Process`,
    /// passing `envelope.recipients` (which already includes any Bcc
    /// addresses) as explicit trailing arguments. A `.delivered` result
    /// here means only "the local MTA's process exited zero and accepted
    /// the handoff" -- actual delivery to each recipient's mailbox, retries,
    /// and TLS are entirely that local MTA's own responsibility from this
    /// point on, not observable by this transport. Throws
    /// `LocalMTAError.nonZeroExit`/`.processLaunchFailed`/`.timedOut` if the
    /// local MTA rejects the handoff outright, rather than returning a
    /// per-recipient failure -- there is no partial-acceptance concept at
    /// this handoff layer.
    public func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        try await runProcess(envelope: envelope, message: message)
        // The local MTA accepted the handoff (zero exit) -- this is the
        // full extent of what this transport can observe; per-recipient
        // delivery from here on is the local MTA's own responsibility.
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["Handed off to local MTA"])))
        }
    }

    private func runProcess(envelope: SMTPEnvelope, message: SignedMessage) async throws {
        // Release review: the addresses go straight into the `sendmail`
        // argv, so check them here as the SMTP path does before RCPT TO.
        try envelope.validate()
        var arguments = config.extraArguments
        switch envelope.mailFrom {
        case .address(let address):
            arguments.append(contentsOf: ["-f", address])
        case .null:
            // FIX #3 (protocol correctness, milestone review): `MAIL
            // FROM:<>` is SMTP *wire* syntax; `sendmail`'s command-line
            // `-f` flag is a separate Unix-argv interface expecting a bare
            // address string. Researched against actual behavior rather
            // than guessed a second time (the previous implementer's `-f
            // "<>"` guess was already wrong once, per the review):
            //  - Exim's own spec (`ch-the_exim_command_line`) explicitly
            //    documents BOTH `-f ''` and `-f '<>'` as valid null-sender
            //    syntax ("An empty sender can be specified either as an
            //    empty string, or as a pair of angle brackets with nothing
            //    between them").
            //  - Empirically verified against the Postfix `sendmail(1)`
            //    compatibility wrapper on this development host (`/usr/sbin
            //    /sendmail`, itself confirmed via `man sendmail` to be
            //    "Postfix to Sendmail compatibility interface" -- exactly
            //    what this transport's own doc comment says
            //    `/usr/sbin/sendmail` conventionally resolves to): both
            //    `-f ""` and `-f "<>"` produce identical accepted behavior
            //    (`sendmail -bv -f "<>" root` and `-f "" root` both report
            //    "Mail Delivery Status Report will be mailed to <>."),
            //    because Postfix's wrapper strips any enclosing angle
            //    brackets from the `-f` argument before use.
            //  - A widely-cited cross-implementation compatibility report
            //    (cyrus-devel mailing list, "sendmail invocation for
            //    'empty sender' bounces") found the *opposite* split
            //    historically: Postfix, Debian SMail, and qmail accepted
            //    `-f ""`, while older Sendmail 8.11.3 required `-f "<>"`
            //    and rejected an empty string outright -- i.e. even that
            //    account doesn't support the original code's `<>`-only
            //    choice as universally correct either.
            // Given real disagreement across implementations historically,
            // and no single form being universally safe, `-f ""` is used
            // here as the more broadly-documented modern convention
            // (explicit in Exim's spec, empirically confirmed on Postfix)
            // -- an informed, documented judgment call, not a blind guess.
            arguments.append(contentsOf: ["-f", ""])
        }
        // FIX #2 layer 2 (security review, CWE-88, defense-in-depth):
        // a literal `--` end-of-options separator, signaling to the local
        // MTA's `getopt`-style argv parser that everything after this
        // point is a positional argument (a recipient), never a flag --
        // even if layer 1 (`SMTPEnvelope`/`ReversePath` rejecting a
        // leading `-` at construction time) is somehow bypassed by a
        // future code path that constructs recipients outside that
        // validated init.
        arguments.append("--")
        arguments.append(contentsOf: envelope.recipients)

        try await Self.execute(
            executablePath: config.executablePath,
            arguments: arguments,
            input: message.rfc5322,
            timeout: config.processTimeout
        )
    }

    /// Launches the process, feeds `input` to stdin, and awaits
    /// termination — all off the actor (a `static` function, so it can't
    /// accidentally touch actor state from a background thread), since
    /// `Process` itself does the real work via its own delegate/callback
    /// machinery, not actor-isolated code.
    private static func execute(
        executablePath: String,
        arguments: [String],
        input: [UInt8],
        timeout: TimeInterval
    ) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        // Milestone review finding (defense-in-depth): `Process` never sets
        // `environment` by default, so the subprocess inherits the full
        // parent environment -- every variable the host process has, handed
        // to the highest-risk new attack surface in this phase (an external
        // binary invoked with caller-influenced argv). An explicit, minimal
        // environment limits what a compromised/malicious local MTA binary
        // -- or a `LD_PRELOAD`/similar environment-based attack riding along
        // in the parent's environment -- can leverage. `PATH` is the only
        // variable genuinely required (`executableURL` is already an
        // absolute path, so `PATH` isn't needed for resolution, but is kept
        // for any `PATH`-relative behavior the MTA binary's own internals
        // might have, e.g. shelling out to `sh`/other tools itself).
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Concurrent stdout/stderr draining (plan's explicit design note):
        // a process that writes enough to one pipe while only the other is
        // being read blocks forever on the full pipe's kernel buffer once
        // it fills -- both must be drained concurrently with each other
        // and with writing stdin, not sequentially. All four tasks below
        // run side by side; only the "wait for termination or timeout"
        // task decides the overall outcome -- the drain/stdin tasks simply
        // run to completion (or get cancelled at scope exit) alongside it.
        let stderrBox = NIOLockedBox<[UInt8]>([])

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                // FIX #7 (concurrency hygiene, milestone review):
                // `FileHandle.availableData` is a blocking, synchronous
                // syscall. Running this read loop directly inside a
                // `TaskGroup` child occupies a Swift Concurrency
                // cooperative-pool worker thread for the blocking read's
                // duration -- under concurrent `LocalMTATransport.send()`
                // calls (exactly what `SMTPMailer`'s bounded-batch fan-out
                // enables), this risks starving the pool of threads needed
                // for other async work in the process. `Self.runBlocking`
                // bridges the whole loop onto a dedicated background
                // thread instead, off the cooperative pool entirely.
                let collected = try await Self.runBlocking {
                    var collected: [UInt8] = []
                    try Self.readToEnd(stderrPipe.fileHandleForReading) { collected.append(contentsOf: $0) }
                    return collected
                }
                stderrBox.value = collected
            }

            group.addTask {
                // sendmail-compatible shims are usually silent on stdout,
                // but a verbose one (or `-v`) could otherwise deadlock the
                // same way an undrained stderr would. Same off-cooperative-
                // pool bridging as the stderr drain above (FIX #7).
                _ = try await Self.runBlocking {
                    try Self.readToEnd(stdoutPipe.fileHandleForReading) { _ in }
                }
            }

            group.addTask {
                let handle = stdinPipe.fileHandleForWriting
                try handle.write(contentsOf: Data(input))
                try handle.close()
            }

            group.addTask {
                try await Self.raceTerminationAgainstTimeout(process: process, stderrBox: stderrBox, timeout: timeout)
            }

            try await group.waitForAll()
        }
    }

    /// Reads `handle` to end of file, passing each chunk to `body`.
    ///
    /// 6.0.1: this used `FileHandle.availableData`, which corelibs
    /// Foundation turns into a `fatalError` on any read error, EINTR
    /// included, so a signal interrupting the read crashed the process
    /// (the test suite hit it on emulated linux/amd64). An interrupted
    /// read is now retried, and any other error is thrown.
    static func readToEnd(_ handle: FileHandle, _ body: (UnsafeRawBufferPointer) -> Void) throws {
        let fd = handle.fileDescriptor
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let (count, error) = buffer.withUnsafeMutableBytes { bytes in
                let count = read(fd, bytes.baseAddress, bytes.count)
                return (count, count < 0 ? errno : 0)
            }
            if count > 0 {
                buffer.withUnsafeBytes { body(UnsafeRawBufferPointer(rebasing: $0.prefix(count))) }
            } else if count == 0 {
                return
            } else if error != EINTR {
                throw POSIXError(POSIXErrorCode(rawValue: error) ?? .EIO)
            }
        }
    }

    /// Bridges a blocking, synchronous closure onto a dedicated background
    /// thread (`DispatchQueue.global(qos: .utility)`), never the Swift
    /// Concurrency cooperative thread pool -- FIX #7's mechanism (see the
    /// stdout/stderr drain call sites above). `@unchecked Sendable`-free:
    /// `T` is constrained `Sendable` and the closure is `@Sendable`, so no
    /// unchecked escape hatch is needed here.
    private static func runBlocking<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            DispatchQueue.global(qos: .utility).async {
                do {
                    continuation.resume(returning: try body())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Races "the process terminates" against "the timeout elapses",
    /// whichever happens first. The loser is cancelled and, for the
    /// timeout case, its still-running `awaitTermination` task is left to
    /// resolve naturally once `process.terminate()` actually takes effect
    /// -- discarded (not awaited further) once this function returns.
    private static func raceTerminationAgainstTimeout(
        process: Process,
        stderrBox: NIOLockedBox<[UInt8]>,
        timeout: TimeInterval
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { race in
            race.addTask {
                try await Self.awaitTermination(process: process, stderrBox: stderrBox)
            }
            race.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(0, timeout) * 1_000_000_000))
                if process.isRunning { process.terminate() }
                throw LocalMTAError.timedOut
            }
            defer { race.cancelAll() }
            try await race.next()
        }
    }

    /// Bridges `Process.terminationHandler` to a continuation with a
    /// single-resume guard.
    ///
    /// Self-check against a double-resume: `Process.terminationHandler` is
    /// documented to fire exactly once per process (either normal exit or
    /// uncaught signal, never both, never twice) -- confirmed by
    /// Foundation's own implementation, which clears the handler after
    /// invoking it. The `resumed` flag below is defense-in-depth on top of
    /// that guarantee, not a workaround for a known double-fire: even if a
    /// future Foundation change (or a platform-specific `Process` behavior
    /// difference) ever violated that contract, this guard makes a
    /// double-resume a silent no-op instead of the fatal "SWIFT TASK
    /// CONTINUATION MISUSE" crash a raw continuation would produce. A
    /// genuine concurrent-double-completion *test* isn't practical without
    /// either forking Foundation's `Process` or invoking private SPI to
    /// fire the handler twice -- this comment plus the guard's presence is
    /// the documented code-review-level self-check the plan calls for when
    /// a real race test isn't practical for a subprocess.
    private static func awaitTermination(process: Process, stderrBox: NIOLockedBox<[UInt8]>) async throws {
        let guardBox = ResumeGuard()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            process.terminationHandler = { proc in
                if proc.terminationStatus == 0 {
                    guardBox.resumeOnce(continuation, .success(()))
                } else {
                    let stderrText = String(decoding: stderrBox.value, as: UTF8.self)
                    guardBox.resumeOnce(
                        continuation,
                        .failure(LocalMTAError.nonZeroExit(code: proc.terminationStatus, stderr: stderrText))
                    )
                }
            }
            do {
                try process.run()
            } catch {
                guardBox.resumeOnce(continuation, .failure(LocalMTAError.processLaunchFailed("\(error)")))
            }
        }
    }
}

/// A `NSLock`-protected single-resume guard shared between
/// `Process.terminationHandler` (invoked from Foundation's own
/// termination-notification thread) and the synchronous `process.run()`
/// failure path -- see `awaitTermination`'s doc comment for why the guard
/// is defense-in-depth, not a workaround for a known double-fire.
/// `@unchecked Sendable`: all mutable state (`resumed`) is behind the lock.
private final class ResumeGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resumeOnce(_ continuation: CheckedContinuation<Void, Error>, _ result: Result<Void, Error>) {
        lock.lock()
        let shouldResume = !resumed
        resumed = true
        lock.unlock()
        guard shouldResume else { return }
        switch result {
        case .success: continuation.resume()
        case .failure(let error): continuation.resume(throwing: error)
        }
    }
}

/// A minimal `NSLock`-protected box for a value crossing from a
/// non-Swift-Concurrency callback context (a pipe-reading loop on a plain
/// `Task`, and `Process.terminationHandler`'s background thread) back into
/// the awaited result. `@unchecked Sendable` is warranted here: all access
/// is serialized by `NSLock`, matching this codebase's established pattern
/// for value types that must cross a callback boundary Swift Concurrency
/// doesn't isolate for you.
final class NIOLockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value

    init(_ value: Value) { self._value = value }

    var value: Value {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); defer { lock.unlock() }; _value = newValue }
    }
}

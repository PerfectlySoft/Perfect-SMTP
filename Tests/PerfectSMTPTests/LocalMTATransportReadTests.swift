//
//  LocalMTATransportReadTests.swift
//  PerfectSMTPTests
//
//  6.0.1: the sendmail pipes were drained with `FileHandle.availableData`,
//  which corelibs Foundation turns into a `fatalError` on any read error,
//  EINTR included ("Interrupted system call", FileHandle.swift:231). The
//  full suite crashed that way on emulated linux/amd64. Reads are now
//  retried when interrupted.
//

import Foundation
import Testing
@testable import PerfectSMTP

struct LocalMTATransportReadTests {
    /// The reading thread's pthread, handed over once it's running.
    private final class ReaderThread: @unchecked Sendable {
        let started = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        var thread: pthread_t?
        var collected: [UInt8] = []
        var error: (any Error)?
    }

    @Test(.timeLimit(.minutes(1)))
    func anInterruptedReadIsRetried() throws {
        // A handler without SA_RESTART, so a blocked read() returns EINTR.
        // (`siginterrupt` is deprecated in glibc; `signal` sets SA_RESTART
        // there, so the flag is cleared through sigaction.)
        signal(SIGUSR1) { _ in }
        var action = sigaction()
        sigaction(SIGUSR1, nil, &action)
        action.sa_flags &= ~SA_RESTART
        sigaction(SIGUSR1, &action, nil)
        let pipe = Pipe()
        let reader = ReaderThread()
        let handle = pipe.fileHandleForReading
        Thread {
            // The test runner's threads may start with SIGUSR1 blocked
            // (then nothing would be interrupted); make sure this one doesn't.
            var unblock = sigset_t()
            sigemptyset(&unblock)
            sigaddset(&unblock, SIGUSR1)
            pthread_sigmask(SIG_UNBLOCK, &unblock, nil)
            reader.thread = pthread_self()
            reader.started.signal()
            do {
                try LocalMTATransport.readToEnd(handle) { reader.collected.append(contentsOf: $0) }
            } catch {
                reader.error = error
            }
            reader.finished.signal()
        }.start()
        reader.started.wait()
        let thread = try #require(reader.thread)
        for _ in 0..<5 {
            usleep(20_000)
            pthread_kill(thread, SIGUSR1)
        }
        try pipe.fileHandleForWriting.write(contentsOf: Data("hello".utf8))
        try pipe.fileHandleForWriting.close()
        #expect(reader.finished.wait(timeout: .now() + 10) == .success)
        #expect(reader.error == nil)
        #expect(String(decoding: reader.collected, as: UTF8.self) == "hello")
    }
}

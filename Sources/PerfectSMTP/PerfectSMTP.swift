//
//  PerfectSMTP.swift
//  PerfectSMTP
//
//  Re-exports the transport-agnostic message/MIME model so `import
//  PerfectSMTP` already gives callers `EmailMessage`, `MIMEComposer`, etc.
//  alongside this target's own channel handlers, protocol state machine,
//  connection pool, Transport strategies, and `SMTPMailer`'s public
//  API (see Documentation/swift6-nio-rewrite-plan.md §9).
//
@_exported import PerfectSMTPCore

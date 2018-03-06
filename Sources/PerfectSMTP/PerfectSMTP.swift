//
//  SMTP.swift
//  Perfect-SMTP
//
//  Created by Rockford Wei on 2016-12-28.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2016 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import Foundation
import PerfectCURL
import PerfectLib
import PerfectHTTP

/// SMTP Common Errors
public enum SMTPError:Error {
	/// void subject is not allowed
	case INVALID_SUBJECT
	/// void sender is not allowed
	case INVALID_FROM
	/// void recipient is not allowed
	case INVALID_RECIPIENT
	/// bad memory allocation
	case INVALID_BUFFER
	/// void mail body is not allowed
	case INVALID_CONTENT
	/// unacceptable protocol
	case INVALID_PROTOCOL
	/// base64 failed
	case INVALID_ENCRYPTION
	
	case general(Int, String)
}

/// SMTP login structure
public struct SMTPClient {
	/// smtp://smtp.mail.server or smtps://smtp.mail.server
	public var url = ""
	/// login name: user@mail.server
	public var username = ""
	/// login secret
	public var password = ""
	/// upgrade connection to use TLS
	public var requiresTLSUpgrade = false
	/// constructor
	/// - parameters:
	///   - url: String, smtp://somewhere or smtps://someelsewhere
	///   - username: String, user@somewhere
	///   - password: String
	public init(url: String = "", username: String = "", password: String = "", requiresTLSUpgrade: Bool = false) {
		self.url = url
		self.username = username
		self.password = password
		self.requiresTLSUpgrade = requiresTLSUpgrade
	}
}

/// email receiver format, "Full Name" <nickname@some.where>
public struct Recipient {
	/// Full Name
	public var name = ""
	/// email address, nickname@some.where
	public var address = ""
	/// constructor
	/// - parameters:
	///   - name: full name of the email receiver / recipient
	///   - address: email address, i.e., nickname@some.where
	public init(name: String = "", address: String = "") {
		self.name = name
		self.address = address
	}
}

/// string extension for express conversion from recipient, etc.
extension String {
	/// get RFC 5322-compliant date for email
	static var rfc5322Date: String {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale.current
		dateFormatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
		let compliantDate = dateFormatter.string(from: Date())
		return compliantDate
	}
	
	/// convert a recipient to standard email format: "Full Name"<nickname@some.where>
	/// - parameters:
	///   - recipient: the email receiver name / address structure
	init(recipient: Recipient) {
		// full name can be ignored
		if recipient.name.isEmpty {
			self = recipient.address
		} else {
			self = "\"\(recipient.name)\" <\(recipient.address)>"
		}
	}
	
	/// convert a group of recipients into an address list, joined by comma
	/// - parameters:
	///   - recipients: array of recipient
	init(recipients: [Recipient]) {
		self = recipients.map{String(recipient: $0)}.joined(separator: ", ")
	}
	
	/// MIME mail header: To/Cc/Bcc + recipients
	/// - parameters:
	///   - prefix: To / Cc or Bcc
	///   - recipients: mailing list
	init(prefix: String, recipients: [Recipient]) {
		let r = String(recipients: recipients)
		self = "\(prefix): \(r)\r\n"
	}
	
	/// get the address info from a recipient, i.e, someone@somewhere -> @somewhere
	var emailSuffix: String {
		get {
			guard let at = index(of: "@") else {
				return self
			}
			return self[at..<endIndex]
		}
	}
	
	/// extract file name from a full path
	var fileNameWithoutPath: String {
		get {
			let segments = self.split(separator: "/")
			return String(segments[segments.count - 1])
		}
	}
	
	/// extract file suffix from a file name
	var suffix: String {
		get {
			let segments = self.split(separator: ".")
			return String(segments[segments.count - 1])
		}
	}
}

private struct EmailBodyGen: CURLRequestBodyGenerator {
	let bytes: [UInt8]
	var offset = 0
	var contentLength: Int? { return bytes.count }
	
	init(_ string: String) {
		bytes = Array(string.utf8)
	}
	
	mutating func next(byteCount: Int) -> [UInt8]? {
		let count = bytes.count
		let remaining = count - offset
		guard remaining > 0 else {
			return nil
		}
		let ret = Array(bytes[offset..<min(byteCount, remaining)])
		offset += ret.count
		return ret
	}
}

/// SMTP mail composer
public class EMail {
	/// boundary for mark different part of the mail
	let boundary = "perfect-smtp-boundary"
	/// login info of a valid mail
	public var client: SMTPClient
	/// mail receivers
	public var to: [Recipient] = []
	/// mail receivers
	public var cc: [Recipient] = []
	/// mail receivers / will not be displayed in to / cc recipients
	public var bcc: [Recipient] = []
	/// mail sender info
	public var from: Recipient = Recipient()
	/// title of the email
	public var subject: String = ""
	/// attachements of the mail - file name with full path
	public var attachments:[String] = []
	/// email content body
	public var content: String = ""
	// text version, to be added with a html version.
	public var text: String = ""
	/// an alternative name of content
	public var html: String {
		get { return content }
		set { content = newValue }
	}
	public var connectTimeoutSeconds: Int = 15
	/// for debugging purposes
	public var debug = false
	
	var progress = 0
	
	/// constructor
	/// - parameters:
	///   - client: SMTP client for login info
	public init(client: SMTPClient) {
		self.client = client
	}
	
	/// transform an attachment into an MIME part
	/// - parameters:
	///   - path: local full path
	///   - mimeType: i.e., text/plain for txt, etc.
	/// - returns
	/// MIME encoded content with boundary
	@discardableResult
	private func attach(path: String, mimeType: String) -> String {
		// extract file name from full path
		let file = path.fileNameWithoutPath
		guard !file.isEmpty else {
			return ""
		}
		do {
			// get base64 encoded text
			guard let data = try encode(path: path) else {
				return ""
			}
			if self.debug {
				print("\(data.utf8.count) bytes attached")
			}
			// pack it up to an MIME part
			return "--\(boundary)\r\nContent-Type: text/plain; name=\"\(file)\"\r\n"
				+ "Content-Transfer-Encoding: base64\r\n"
				+ "Content-Disposition: attachment; filename=\"\(file)\"\r\n\r\n\(data)\r\n"
		} catch {
			return ""
		}
	}
	
	/// encode a file by base64 method
	/// - parameters:
	///   - path: full path of the file to encode
	/// - returns:
	/// base64 encoded text
	@discardableResult
	private func encode(path: String) throws -> String? {
		let fd = File(path)
		try fd.open(.read)
		guard let buffer = try fd.readSomeBytes(count: fd.size).encode(.base64) else {
			fd.close()
			throw SMTPError.INVALID_ENCRYPTION
		}
		if self.debug {
			print("encode \(fd.size) -> \(buffer.count)")
		}
		var wraped = [UInt8]()
		let szline = 78
		var cursor = 0
		let newline:[UInt8] = [13, 10]
		while cursor < buffer.count {
			var mark = cursor + szline
			if mark >= buffer.count {
				mark = buffer.count
			}
			wraped.append(contentsOf: buffer[cursor ..< mark])
			wraped.append(contentsOf: newline)
			cursor += szline
		}
		fd.close()
		wraped.append(0)
		return String(validatingUTF8: wraped)
	}
	
	private func makeBody() throws -> String {
		// !FIX! quoted printable?
		var body = "Date: \(String.rfc5322Date)\r\n"
		progress = 0
		// add the "To: " section
		if to.count > 0 {
			body += String(prefix: "To", recipients: to)
		}
		// add the "From: " section
		if from.address.isEmpty {
			throw SMTPError.INVALID_FROM
		} else {
			let f = String(recipient: from)
			body += "From: \(f)\r\n"
		}
		// add the "Cc: " section
		if cc.count > 0 {
			body += String(prefix: "Cc", recipients: cc)
		}
		// add the "Bcc: " section
		if bcc.count > 0 {
			body += String(prefix: "Bcc", recipients: bcc)
		}
		// add the uuid of the email to avoid duplicated shipment
		let uuid = UUID().string
		body += "Message-ID: <\(uuid).Perfect-SMTP\(from.address.emailSuffix)>\r\n"
		// add the email title
		if subject.isEmpty {
			throw SMTPError.INVALID_SUBJECT
		} else {
			body += "Subject: \(subject)\r\n"
		}
		// mark the content type
		body += "MIME-Version: 1.0\r\nContent-type: multipart/alternative; boundary=\"\(boundary)\"\r\n\r\n"
		// add the html / plain text content body
		if content.isEmpty && text.isEmpty {
			throw SMTPError.INVALID_CONTENT
		} else {
			if !text.isEmpty {
				body += "--\(boundary)\r\nContent-Type: text/plain; charset=UTF-8; format=flowed\r\n\r\n\(text)\r\n\r\n"
			}
			if !content.isEmpty {
				body += "--\(boundary)\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n\(content)\r\n\r\n"
			}
		}
		// add the attachements
		body += attachments.map { attach(path: $0, mimeType: MimeType.forExtension($0.suffix)) }.joined(separator: "\r\n")
		// end of the attachements
		body += "--\(boundary)--\r\n"
		return body
	}
	
	private func getResponse() throws -> CURLResponse {
		let recipients = to + cc + bcc
		guard recipients.count > 0 else {
			throw SMTPError.INVALID_RECIPIENT
		}
		let body = try makeBody()
		var options: [CURLRequest.Option] = (debug ? [.verbose] : []) + [
			.mailFrom(from.address),
			.userPwd("\(client.username):\(client.password)"),
			.upload(EmailBodyGen(body)),
			.connectTimeout(connectTimeoutSeconds)]
		options.append(contentsOf: recipients.map { .mailRcpt($0.address) })
		if client.url.lowercased().hasPrefix("smtps") || client.requiresTLSUpgrade {
			options.append(.useSSL)
		}
		let request = CURLRequest(client.url, options: options)
		return try request.perform()
	}
	
	public func send() throws {
		let response = try getResponse()
		let code = response.responseCode
		guard code > 199 && code < 300 else {
			throw SMTPError.general(code, response.bodyString)
		}
	}
	
	/// send an email with the current settings
	/// - parameters:
	///   - completion: once sent, callback to the main thread with curl code, header & body string
	/// - throws:
	/// SMTPErrors
	public func send(completion: @escaping ((Int, String, String) -> Void)) throws {
		let response = try getResponse()
		let code = response.responseCode
		let body = response.bodyString
		completion(code, "", body)
	}
}



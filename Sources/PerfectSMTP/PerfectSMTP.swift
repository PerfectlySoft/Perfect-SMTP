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

/// Headers for pipe i/o
#if os(Linux)
  import LinuxBridge
#else
  import Darwin
#endif

import Foundation

import PerfectThread

/// Header for CURL options macro
import cURL

/// Header for base64 encoding
import PerfectCrypto

/// Header for CURL functions
import PerfectCURL

/// Headers for UUID
import PerfectLib

/// Headers for MIME
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
}//end enum

/// SMTP login structure
public struct SMTPClient {

  /// smtp://smtp.mail.server or smtps://smtp.mail.server
  public var url = ""

  /// login name: user@mail.server
  public var username = ""

  /// login secret
  public var password = ""
    
  /// upgrade connection to use TLS
  public var requiresTLSUpgrade

  /// constructor
  /// - parameters:
  ///   - url: String, smtp://somewhere or smtps://someelsewhere
  ///   - username: String, user@somewhere
  ///   - password: String
  public init(url: String = "", username: String = "", password: String = "", requiresTLSUpgrade = false) {
    self.url = url
    self.username = username
    self.password = password
    self.requiresTLSUpgrade = requiresTLSUpgrade
  }//end init
}//end SMTPClient

/// email receiver format, "Full Name"<nickname@some.where>
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
  }//end init
}//end struct Recipient

/// string extension for express conversion from recipient, etc.
extension String {

  /// get RFC 5322-compliant date for email
  public static var rfc5322Date: String {
    let dateFormatter = DateFormatter()
    dateFormatter.locale = Locale.current
    dateFormatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
    let compliantDate = dateFormatter.string(from: Date())
    return compliantDate
  }

  /// convert a recipient to standard email format: "Full Name"<nickname@some.where>
  /// - parameters:
  ///   - recipient: the email receiver name / address structure
  public init(recipient: Recipient) {

    // full name can be ignored
    if recipient.name.isEmpty {
      self = recipient.address
    }else {
      self =  "\"\(recipient.name)\"<\(recipient.address)>"
    }//end if
  }//end init

  /// convert a group of recipients into an address list, joined by comma
  /// - parameters:
  ///   - recipients: array of recipient
  public init(recipients: [Recipient]) {
    self = recipients.map{String(recipient: $0)}.reduce("") {$0.isEmpty ? $1: $0 + ", " + $1}
  }//end init

  /// MIME mail header: To/Cc/Bcc + recipients
  /// - parameters:
  ///   - prefix: To / Cc or Bcc
  ///   - recipients: mailing list
  public init(prefix: String, recipients: [Recipient]) {
    let r = String(recipients: recipients)
    self = "\(prefix): \(r)\r\n"
  }//end init

  /// get the address info from a recipient, i.e, someone@somewhere -> @somewhere
  public var emailSuffix: String {
    get {
      guard let at = self.index(of: "@") else {
        return self
      }//end at
      return self[at..<self.endIndex]
    }//end get
  }//end mailSuffix

  /// extract file name from a full path
  public var fileNameWithoutPath: String {
    get {
      let segments = self.split(separator: "/")
      return String(segments[segments.count - 1])
    }//end get
  }//end fileNameWithoutPath

  /// extract file suffix from a file name
  public var suffix: String {
    get {
      let segments = self.split(separator: ".")
      return String(segments[segments.count - 1])
    }//end get
  }//end suffix

}//end String


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
  }//end html

  /// for debugging purposes
  public var debug = false

  /// for callback only, do not use it!
  public var progress = 0

  /// for callback only, do not use it!
  public var body = ""

  /// constructor
  /// - parameters:
  ///   - client: SMTP client for login info
  public init(client: SMTPClient) {
    self.client = client
  }//end Int

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
    }//end guard

    do {
      // get base64 encoded text
      guard let data = try encode(path: path) else {
        return ""
      }//end guard

      if self.debug {
        print("\(data.utf8.count) bytes attached")
      }//end if

      // pack it up to an MIME part
      return "--\(boundary)\r\nContent-Type: text/plain; name=\"\(file)\"\r\n"
        + "Content-Transfer-Encoding: base64\r\n"
        + "Content-Disposition: attachment; filename=\"\(file)\"\r\n\r\n\(data)\r\n"
    } catch {
      return ""
    }//end do
  }//end attach

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
    }//end let
    if self.debug {
      print("encode \(fd.size) -> \(buffer.count)")
    }//end if
    var wraped = [UInt8]()
    let szline = 78
    var cursor = 0
    let newline:[UInt8] = [13, 10]
    while cursor < buffer.count {
      var mark = cursor + szline
      if mark >= buffer.count {
        mark = buffer.count
      }//end if
      wraped.append(contentsOf: buffer[cursor ..< mark])
      wraped.append(contentsOf: newline)
      cursor += szline
    }//end while
    fd.close()
    wraped.append(0)
    return String(validatingUTF8: wraped)
  }//end encode

  /// send an email with the current settings
  /// - parameters:
  ///   - completion: once sent, callback to the main thread with curl code, header & body string
  /// - throws:
  /// SMTPErrors
  public func send(completion: @escaping ((Int, String, String)->Void)) throws {

    // merge all recipients
    let recipients = to + cc + bcc

    // validate recipients
    guard recipients.count > 0 else {
      throw SMTPError.INVALID_RECIPIENT
    }//end guard

    self.body = "Date: \(String.rfc5322Date)\r\n"
    progress = 0
    // add the "To: " section
    if to.count > 0 {
      body += String(prefix: "To", recipients: to)
    }//end if

    // add the "From: " section
    if from.address.isEmpty {
      throw SMTPError.INVALID_FROM
    }else {
      let f = String(recipient: from)
      body += "From: \(f)\r\n"
    }//end if

    // add the "Cc: " section
    if cc.count > 0 {
      body += String(prefix: "Cc", recipients: cc)
    }//end if

    // add the "Bcc: " section
    if bcc.count > 0 {
      body += String(prefix: "Bcc", recipients: bcc)
    }//end if

    // add the uuid of the email to avoid duplicated shipment
    let uuid = UUID().string
    body += "Message-ID: <\(uuid).Perfect-SMTP\(from.address.emailSuffix)>\r\n"

    // add the email title
    if subject.isEmpty {
      throw SMTPError.INVALID_SUBJECT
    }else{
      body += "Subject: \(subject)\r\n"
    }//end if

    // mark the content type
    body += "MIME-Version: 1.0\r\nContent-type: multipart/alternative; boundary=\"\(boundary)\"\r\n\r\n"

    // add the html / plain text content body
    if content.isEmpty && text.isEmpty {
      throw SMTPError.INVALID_CONTENT
    }else {
      if !text.isEmpty {
        body += "--\(boundary)\r\nContent-Type: text/plain; charset=UTF-8; format=flowed\r\n\r\n\(text)\r\n\r\n"
      }
      if !content.isEmpty {
        body += "--\(boundary)\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n\(content)\r\n\r\n"
      }
    }//end if

    // add the attachements
    body += attachments.map{ attach(path: $0, mimeType: MimeType.forExtension($0.suffix))}.joined(separator: "\r\n")

    // end of the attachements
    body += "--\(boundary)--\r\n"

    // print(body)
    // load the curl object
    let curl = CURL(url: client.url)

    if self.debug {
      let _ = curl.setOption(CURLOPT_VERBOSE, int: 1)
      let _ = curl.setOption(CURLOPT_HEADER, int: 1)
    }//end if

    // TO FIX: ssl requires a certificate, how to get one???
    if client.url.lowercased().hasPrefix("smtps")
        || (client.url.lowercased().hasPrefix("smtp") && self.requiresTLSUpgrade) {
      let _ = curl.setOption(CURLOPT_USE_SSL, int: Int(CURLUSESSL_ALL.rawValue))

      // otherwise just non-secured smtp protocol
    }else if !client.url.lowercased().hasPrefix("smtp") {
      throw SMTPError.INVALID_PROTOCOL
    }//end if

    // for debug the session
    // let _ = curl.setOption(CURLOPT_VERBOSE, int: 1)

    // set the mail sender info
    let _ = curl.setOption(CURLOPT_MAIL_FROM, s: from.address)

    // set the mail receiver info
    recipients.forEach { let _ = curl.setOption(CURLOPT_MAIL_RCPT, s: $0.address) }

    // set the login
    let _ = curl.setOption(CURLOPT_USERNAME, s: client.username)
    let _ = curl.setOption(CURLOPT_PASSWORD, s: client.password)

    // set the post method
    let _ = curl.setOption(CURLOPT_UPLOAD, int: 1)

    // set the mime size
    let _ = curl.setOption(CURLOPT_INFILESIZE, int: body.utf8.count)

    let me = Unmanaged<AnyObject>.passRetained(self as AnyObject).toOpaque()

    let _ = curl.setOption(CURLOPT_READFUNCTION, f: { target, sz, items, opaque in
      guard let pointer = opaque else {
        print("curl callback failed")
        return 0
      }//end guard

      let this = Unmanaged<EMail>.fromOpaque(pointer).takeUnretainedValue()

      let szblock = sz * items;

      let remain = this.body.utf8.count - this.progress
      if remain <= 0 {
        print("return 0")
        return 0
      }//end if
      let result = this.body.withCString { ptr -> Int in
        let size = remain > szblock ? szblock : remain
        #if os(Linux)
          memcpy(target!, ptr.advanced(by: this.progress), size)
        #else
          memcpy(target, ptr.advanced(by: this.progress), size)
        #endif
        return size
      }//end with
      this.progress += result
      return result
    })

    let _ = curl.setOption(CURLOPT_READDATA, v: me)

    // asynchronized calling
    Threading.dispatch {
      let r = curl.performFully()
      //release pipeline
      //callback
      var r1 = r.1
      r1.append(0)
      var r2 = r.2
      r2.append(0)
      completion(r.0, String(cString: r1), String(cString: r2))
    }//end perform
  }//end send
}//end class

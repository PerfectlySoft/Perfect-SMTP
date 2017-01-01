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

/// Header for CURL options macro
import cURL

/// Header for base64 encoding
import CoreFoundation
import Foundation

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
}//end enum

/// SMTP login structure
public struct SMTPClient {

  /// smtp://smtp.mail.server or smtps://smtp.mail.server
  public var url = ""

  /// login name: user@mail.server
  public var username = ""

  /// login secret
  public var password = ""
}//end SMTPClient

/// email receiver format, "Full Name"<nickname@some.where>
public struct Recipient {

  /// Full Name
  var name = ""

  /// email address, nickname@some.where
  var address = ""

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

  /// convert a string buffer into a FILE (pipe) pointer for reading, for CURL upload operations
  public var asFileNumber:Int32 {
    get {

      // setup a pipe line
      var p:[Int32] = [0, 0]
      let result = pipe(&p)
      guard result == 0 else {
        return -1
      }//end result

      // write string to pipe
      let fd = fdopen(p[1], "w")
      let _ = fwrite(self, 1, self.utf8.count, fd)

      // close pipe writing end for reading
      fclose(fd)

      // return the pipe reading end
      return p[0]
    }//end get
  }//end freader

  /// get the address info from a recipient, i.e, someone@somewhere -> @somewhere
  public var emailSuffix: String {
    get {
      guard let at = self.characters.index(of: "@") else {
        return self
      }//end at
      return self[at..<self.endIndex]
    }//end get
  }//end mailSuffix

  /// extract file name from a full path
  public var fileNameWithoutPath: String {
    get {
      let segments = self.characters.split(separator: "/")
      return String(segments[segments.count - 1])
    }//end get
  }//end fileNameWithoutPath

  /// extract file suffix from a file name 
  public var suffix: String {
    get {
      let segments = self.characters.split(separator: ".")
      return String(segments[segments.count - 1])
    }//end get
  }//end suffix
}//end String


/// SMTP mail composer
public struct EMail {

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

  /// an alternative name of content
  public var html: String {
    get { return content }
    set { content = html }
  }//end html

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
      let data = try encode(path: path)
      guard !data.isEmpty else {
        return ""
      }//end guard

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
  private func encode(path: String) throws -> String {
    var lines = ""
    do {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      let longStr = data.base64EncodedString()
      var i = longStr.startIndex
      let size = 78
      while(longStr.distance(from: i, to: longStr.endIndex) > size) {
        let j = longStr.index(i, offsetBy: size)
        let line = longStr[i..<j] + "\r\n"
        lines += line
        i = j
      }//end while
      if longStr.distance(from: i, to: longStr.endIndex) > 0 {
        let line = longStr[i..<longStr.endIndex] + "\r\n"
        lines += line
      }//end if
    }catch {
      throw SMTPError.INVALID_BUFFER
    }//end do
    return lines
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

    // print a timestamp to the email
    var timestamp = time(nil)
    let now = String(cString: asctime(localtime(&timestamp))!)
    var body = "Date: \(now)"

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

    body += "Message-ID: <\(uuid)\(from.address.emailSuffix)>\r\n"

    // add the email title
    if subject.isEmpty {
      throw SMTPError.INVALID_SUBJECT
    }else{
      body += "Subject: \(subject)\r\n"
    }//end if

    // mark the content type
    body += "MIME-Version: 1.0\r\nContent-type: multipart/mixed; boundary=\"\(boundary)\"\r\n\r\n"

    // add the html / plain text content body
    if content.isEmpty {
      throw SMTPError.INVALID_CONTENT
    }else {
      body += "--\(boundary)\r\nContent-Type: text/html;charset=utf8\r\n\r\n\(content)\r\n\r\n"
    }//end if

    // add the attachements
    body += attachments.map{ attach(path: $0, mimeType: MimeType.forExtension($0.suffix))}.joined(separator: "\r\n")

    // end of the attachements
    body += "--\(boundary)--\r\n"

    print(body)
    // load the curl object
    let curl = CURL(url: client.url)

    // TO FIX: ssl requires a certificate, how to get one???
    if client.url.lowercased().hasPrefix("smtps") {
      let _ = curl.setOption(CURLOPT_USE_SSL, int: Int(CURLUSESSL_ALL.rawValue))

      // otherwise just non-secured smtp protocol
    }else if !client.url.lowercased().hasPrefix("smtp") {
      throw SMTPError.INVALID_PROTOCOL
    }//end if

    // for debug the session
    let _ = curl.setOption(CURLOPT_VERBOSE, int: 1)

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

    // transform the body content into a file number for uploading
    var data = body.asFileNumber

    guard data > 0 else {
      throw SMTPError.INVALID_BUFFER
    }//END guard

    // setup data
    let _ = curl.setOption(CURLOPT_READDATA, v: &data)

    let _ = curl.setOption(CURLOPT_READFUNCTION, f: { buf, itm, sz, pData in
      let ptr = unsafeBitCast(pData, to: UnsafePointer<Int32>.self)
      return read(ptr.pointee, buf, sz)
    })//end reading

    // asynchronized calling
    let _ = curl.perform {
      // clean up
      close(data)
      // call back
      completion($0, String(cString: $1), String(cString: $2))
    }//end perform
  }//end send
}//end class

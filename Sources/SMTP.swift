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
#if os(Linux)
  import LinuxBridge
#else
  import Darwin
#endif
import cURL
import COpenSSL
import PerfectCURL
import PerfectLib

public enum SMTPError:Error {
  case INVALID_SUBJECT
  case INVALID_FROM
  case INVALID_RECIPIENT
  case INVALID_BUFFER
  case INVALID_CONTENT
  case INVALID_PROTOCOL
}//end enum

public struct SMTPClient {
  private static var openssl_loaded = false
  public var url = ""
  public var username = ""
  public var password = ""
  public init(url: String, username: String, password: String) {
    self.url = url
    self.username = username
    self.password = password
    // singleton
    if SMTPClient.openssl_loaded {
      return
    }//end if
    SSL_load_error_strings()
    ERR_load_BIO_strings()
    OPENSSL_add_all_algorithms_noconf()
    SMTPClient.openssl_loaded = true
  }//init
}//end SMTPClient

public struct Recipient {
  var name = ""
  var address = ""
  public init(name: String = "", address: String = "") {
    self.name = name
    self.address = address
  }//end init
}//end struct Recipient

extension String {
  public init(recipient: Recipient) {
    if recipient.name.isEmpty {
      self = recipient.address
    }else {
      self =  "\"\(recipient.name)\"<\(recipient.address)>"
    }//end if
  }//end init

  public init(recipients: [Recipient]) {
    self = recipients.map{String(recipient: $0)}.reduce("") {$0.isEmpty ? $1: $0 + ", " + $1}
  }//end init

  public init(prefix: String, recipients: [Recipient]) {
    let r = String(recipients: recipients)
    self = "\(prefix): \(r)\r\n"
  }//end init

  public var asFILE:UnsafeMutablePointer<FILE>? {
    get {
      var p:[Int32] = [0, 0]
      let result = pipe(&p)
      guard result == 0 else {
        return nil
      }//end result

      let fi = fdopen(p[0], "rb")
      let fo = fdopen(p[1], "wb")
      let _ = fwrite(self, 1, self.utf8.count, fo)
      fclose(fo)
      return fi ?? nil
    }//end get
  }//end freader

  public var emailSuffix: String {
    get {
      guard let at = self.characters.index(of: "@") else {
        return self
      }//end at
      return self[at..<self.endIndex]
    }//end get
  }//end mailSuffix

  public var fileNameWithoutPath: String {
    get {
      let segments = self.characters.split(separator: "/")
      return String(segments[segments.count - 1])
    }//end get
  }//end fileNameWithoutPath
}//end String

public struct EMail {

  let boundary = "perfect-smtp-boundary"
  public var client: SMTPClient
  public var to: [Recipient] = []
  public var cc: [Recipient] = []
  public var bcc: [Recipient] = []
  public var from: Recipient = Recipient()
  public var subject: String = ""
  public var content: String = ""

  public var html: String {
    get { return content }
    set { content = html }
  }//end html

  public init(client: SMTPClient) {
    self.client = client
  }//end Int

  private var attachments:[String] = []

  public mutating func attach(path: String, mimeType: String) {
    let file = path.fileNameWithoutPath
    guard !file.isEmpty else {
      return
    }//end guard

    let data = encode(fromFile: path)
    guard !data.isEmpty else {
      return
    }//end guard

    let body = "--\(boundary)\r\nContent-Type: text/plain; name=\"\(file)\"\r\n"
    + "Content-Transfer-Encoding: base64\r\n"
    + "Content-Disposition: attachment; filename=\"\(file)\"\r\n\r\n\(data)\r\n"

    attachments.append(body)
  }//end attach

  private func encode(fromFile: String) -> String {
    guard let fd = fopen(fromFile, "rb") else {
      return ""
    }//end fd

    var pipes:[Int32] = [0,0]
    let res = pipe(&pipes)
    guard res == 0 else {
      return ""
    }//end pipe

    let b64 = BIO_new(BIO_f_base64())
    let bio = BIO_new_fd(pipes[1], BIO_NOCLOSE)
    BIO_push(b64, bio)

    var buf:[CChar] = []
    let size = 512
    var received = 0

    buf.reserveCapacity(size)
    buf.withUnsafeBufferPointer{ pBuf in
      let pRaw = unsafeBitCast(pBuf.baseAddress, to: UnsafeMutableRawPointer.self)
      repeat {
        memset(pRaw, 0, size)
        received = fread(pRaw, 1, size, fd)
        if received < 1 {
          break
        }//end if
        BIO_write(b64, pRaw, Int32(received))
      }while(received >= size)
    }//end buf

    BIO_ctrl(b64,BIO_CTRL_FLUSH,0,nil)

    fclose(fd)
    close(pipes[1])
    BIO_free_all(b64)


    let line = 78

    var longStr = ""
    buf.withUnsafeBufferPointer{ pBuf in
      let pRaw = unsafeBitCast(pBuf.baseAddress, to: UnsafeMutableRawPointer.self)
      repeat {
        memset(pRaw, 0, size)
        received = read(pipes[0], pRaw, line)
        if received < 1 {
          break
        }//end if
        let str = String(cString: buf) + "\r\n"
        longStr += str
      }while(received >= line)
    }//end buf
    close(pipes[0])
    return longStr
  }//end encode

  public func send(completion: @escaping ((Int, String, String)->Void)) throws {

    let recipients = to + cc + bcc

    guard recipients.count > 0 else {
      throw SMTPError.INVALID_RECIPIENT
    }//end guard

    var timestamp = time(nil)
    let now = String(cString: asctime(localtime(&timestamp))!)
    var body = "Date: \(now)"

    if to.count > 0 {
      body += String(prefix: "To", recipients: to)
    }//end if

    if from.address.isEmpty {
      throw SMTPError.INVALID_FROM
    }else {
      let f = String(recipient: from)
      body += "From: \(f)\r\n"
    }//end if

    if cc.count > 0 {
      body += String(prefix: "Cc", recipients: cc)
    }//end if

    if bcc.count > 0 {
      body += String(prefix: "Bcc", recipients: bcc)
    }//end if

    let uuid = UUID().string

    body += "Message-ID: <\(uuid)\(from.address.emailSuffix)>\r\n"

    if subject.isEmpty {
      throw SMTPError.INVALID_SUBJECT
    }else{
      body += "Subject: \(subject)\r\n"
    }//end if


    body += "MIME-Version: 1.0\r\nContent-type: multipart/mixed; boundary=\"\(boundary)\"\r\n\r\n"

    if content.isEmpty {
      throw SMTPError.INVALID_CONTENT
    }else {
      body += "--\(boundary)\r\nContent-Type: text/html;charset=utf8\r\n\r\n\(content)\r\n\r\n"
    }//end if


    body += attachments.joined(separator: "\r\n")

    body += "--\(boundary)--\r\n"

    print(body)

    let curl = CURL(url: client.url)
    if client.url.lowercased().hasPrefix("smtps") {
      let _ = curl.setOption(CURLOPT_USE_SSL, int: Int(CURLUSESSL_ALL.rawValue))
    }else if !client.url.lowercased().hasPrefix("smtp") {
      throw SMTPError.INVALID_PROTOCOL
    }//end if

    let _ = curl.setOption(CURLOPT_VERBOSE, int: 1)
    let _ = curl.setOption(CURLOPT_MAIL_FROM, s: from.address)
    recipients.forEach { let _ = curl.setOption(CURLOPT_MAIL_RCPT, s: $0.address) }
    let _ = curl.setOption(CURLOPT_USERNAME, s: client.username)
    let _ = curl.setOption(CURLOPT_PASSWORD, s: client.password)
    let _ = curl.setOption(CURLOPT_UPLOAD, int: 1)
    let _ = curl.setOption(CURLOPT_INFILESIZE, int: body.utf8.count)
    guard let data = body.asFILE else {
      throw SMTPError.INVALID_BUFFER
    }//END guard

    let _ = curl.setOption(CURLOPT_READDATA, v: data)
    let r = curl.performFully()
    completion(r.0, String(cString: r.1), String(cString: r.2))
  }//end send
}//end class

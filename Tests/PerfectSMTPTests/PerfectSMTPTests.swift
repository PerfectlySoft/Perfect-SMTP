import XCTest
import PerfectLib
import PerfectCURL

@testable import PerfectSMTP

class PerfectSMTPTests: XCTestCase {
    func testExample() {
      var email = EMail(client: SMTPClient(url: "smtp://smtp.gmx.com", username: "judysmith1964@gmx.com", password:"yourpassword"))
      email.subject = "hello"
      email.from = Recipient(name: "Judith Smith", address: "judysmith1964@gmx.com")
      email.content = "<h1>这是一个测试</h1><hr><img src='http://www.perfect.org/images/perfect-logo-2-0.svg'>"
      email.to.append(email.from)
      email.cc.append(Recipient(address: "rockywei@gmx.com"))

      let x = self.expectation(description: "sending mail")
      do {
        let fa = File("/tmp/hello.txt")
        try fa.open(.write)
        try fa.write(string: "Hello, World!")
        fa.close()
        let fb = File("/tmp/hola.txt")
        try fb.open(.write)
        try fb.write(string: "中国🇨🇳Canada🇨🇦")
        fb.close()
        email.attachments.append("/tmp/hello.txt")
        email.attachments.append("/tmp/hola.txt")
        let curl = CURL(url: "https://www.perfect.org/docs/images/China-Flag-icon.png")
        let r = curl.performFully()
        if r.0 == 0 {
          let fc = File("/tmp/china.png")
          try fc.open(.write)
          try fc.write(bytes: r.2)
          fc.close()
          email.attachments.append("/tmp/china.png")
        }

        try email.send { code, header, body in
          print(code)
          print(header)
          print(body)
          x.fulfill()
        }//end send
      }catch(let err) {
        XCTFail("\(err)")
      }
      self.waitForExpectations(timeout: 30) { err in
        if err != nil {
          XCTFail("time out \(err)")
        }//end if
      }
    }


    static var allTests : [(String, (PerfectSMTPTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}

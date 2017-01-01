import XCTest
@testable import SMTP

class SMTPTests: XCTestCase {
    func testExample() {
      var email = EMail(client: SMTPClient(url: "smtp://smtp.gmx.com", username: "judysmith1964@gmx.com", password:"yourpassword"))
      email.subject = "hello"
      email.from = Recipient(name: "Judith Smith", address: "judysmith1964@gmx.com")
      email.content = "<h1>这是一个测试</h1><hr><img src='http://www.perfect.org/images/perfect-logo-2-0.svg'>"
      email.to.append(email.from)
      email.cc.append(Recipient(address: "rockywei@gmx.com"))

      email.attachments.append("/tmp/hello.txt")
      email.attachments.append("/tmp/hola.txt")
      email.attachments.append("/tmp/qr.gif")
      let x = self.expectation(description: "sending mail")
      do {
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


    static var allTests : [(String, (SMTPTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}

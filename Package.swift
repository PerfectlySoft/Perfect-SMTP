import PackageDescription
#if os(Linux)
import SwiftGlibc
#else
import Darwin
#endif
var url = "https://github.com/PerfectlySoft/Perfect-CURL.git"
if let urlenv = getenv("URL_PERFECT_CURL") {
    url = String(cString: urlenv)
}
let package = Package(
    name: "PerfectSMTP",
    dependencies: [
    .Package(url: url, majorVersion: 3)
  ]
)

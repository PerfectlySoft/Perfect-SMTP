import PackageDescription

let package = Package(
    name: "PerfectSMTP",
    dependencies: [
    .Package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", majorVersion: 2),
    .Package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", majorVersion: 2)
  ]
)

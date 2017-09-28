import PackageDescription

let package = Package(
    name: "PerfectSMTP",
    dependencies: [
    .Package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", majorVersion: 3),
    .Package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", majorVersion: 3)
  ]
)

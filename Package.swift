import PackageDescription

let package = Package(
    name: "SMTP",
    dependencies: [
    .Package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", majorVersion: 2, minor: 0),
    .Package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", majorVersion: 2, minor: 0)
    ]
)

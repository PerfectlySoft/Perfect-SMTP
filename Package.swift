// swift-tools-version:4.0
import PackageDescription
let package = Package(name: "PerfectSMTP", 
	products: [.library(name: "PerfectSMTP",targets: ["PerfectSMTP"]),],
    dependencies: [
	.package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", from: "3.0.6"),
	],
    targets: [
        .target(
            name: "PerfectSMTP",
            dependencies: ["PerfectCURL"]),
//        .testTarget(
//            name: "PerfectSMTPTests",
//            dependencies: ["PerfectSMTP"]),
    ])

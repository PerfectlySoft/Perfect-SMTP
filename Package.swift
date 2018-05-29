// swift-tools-version:4.0
import PackageDescription
let package = Package(name: "PerfectSMTP", 
	products: [.library(name: "PerfectSMTP",targets: ["PerfectSMTP"]),],
    dependencies: [
		.package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", .branch("master")),
	],
    targets: [
        .target(
            name: "PerfectSMTP",
            dependencies: ["PerfectCURL"]),
    ])
// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PerfectSMTP",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .library(name: "PerfectSMTPCore", targets: ["PerfectSMTPCore"]),
        .library(name: "PerfectSMTP", targets: ["PerfectSMTP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        // Pinned to an exact version, not `from:` — `_CryptoExtras` (needed
        // for RSA-SHA256 DKIM signing) is an underscore-prefixed, semi-
        // stable SPI module per plan §4.6, so an unpinned range risks a
        // silent behavior/API change under this SPI on a routine update.
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ],
    targets: [
        // Foundation + Crypto/_CryptoExtras only. No NIO import — value
        // types, MIME builder, RFC 2047 header encoder, dot-stuffing/QP/
        // base64 encoders, reply/error/result model, and (Phase 2) the DKIM
        // signer. This boundary is a deliberate compile-time enforcement
        // that MIME composition and DKIM signing can never reach into a
        // live channel (see Documentation/swift6-nio-rewrite-plan.md §4.1).
        .target(
            name: "PerfectSMTPCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectSMTPCoreTests",
            dependencies: [
                "PerfectSMTPCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // Transport layer target. Channel handlers, the protocol state
        // machine, the connection-pool actor, Transport strategies, and
        // SMTPMailer's public API land here starting Phase 1 (see
        // Documentation/swift6-nio-rewrite-plan.md §9).
        .target(
            name: "PerfectSMTP",
            dependencies: [
                "PerfectSMTPCore",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectSMTPTests",
            dependencies: [
                "PerfectSMTP",
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)

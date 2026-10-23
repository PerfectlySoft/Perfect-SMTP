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
        // 2.86.0: the library itself needs 2.75.0 (`syncOperations
        // .removeHandler(context:)`); the tests need 2.86.0, the first
        // release whose `EmbeddedChannel` accepts the `autoRead` option.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        // A range, not an exact pin: an exact pin in a library makes
        // resolution fail for any app that also needs a different
        // swift-crypto. `_CryptoExtras` is underscore-prefixed, but the only
        // part used here (`_RSA.Signing` PEM/DER init, `keySizeInBits`,
        // PKCS#1 v1.5 sign/verify) is unchanged from 3.4.0 (the first
        // release with `Sendable` RSA keys and the `unsafe*Representation`
        // initializers the tests use) through 4.5.2; both ends of the range
        // are built and tested. Matches Perfect-NIO's own 3.x..<5 range.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.4.0"..<"5.0.0"),
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
        // machine, the connection pool, Transport strategies, and
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

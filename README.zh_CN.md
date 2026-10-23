# Perfect - SMTP 简单邮件协议 [English](README.md)

<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://github.com/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_1_Star.jpg" alt="Star Perfect On Github" />
    </a>
    <a href="https://gitter.im/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_2_Git.jpg" alt="Chat on Gitter" />
    </a>
    <a href="https://twitter.com/perfectlysoft" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_3_twit.jpg" alt="Follow Perfect on Twitter" />
    </a>
    <a href="http://perfect.ly" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_4_slack.jpg" alt="Join the Perfect Slack" />
    </a>
</p>

<p align="center">
    <a href="https://www.swift.org/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-6.2%2B-orange.svg?style=flat" alt="Swift 6.2+">
    </a>
    <a href="https://www.swift.org/platform-support/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B%20%7C%20Linux-lightgray.svg?style=flat" alt="Platforms macOS 12+ | Linux">
    </a>
    <a href="LICENSE" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0">
    </a>
    <a href="http://twitter.com/PerfectlySoft" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat" alt="PerfectlySoft Twitter">
    </a>
</p>

> **翻译说明：** 本文档由机器翻译并经过人工审阅，但尚未经过以 SMTP/DKIM 等协议
> 术语为母语背景的技术审校。协议术语（STARTTLS、DKIM、MTA-STS、SASL 等）保留英文
> 原文以避免歧义。如发现术语或语义不准确之处，请以 [English](README.md) 版本为准，
> 并欢迎提交修正。

Perfect-SMTP 是一个基于 Swift 6.2 / SwiftNIO 从零编写的 SMTP 客户端。它不是对
libcurl 或其他邮件库的封装——它自己实现了 SMTP 线路协议，包括自己的 STARTTLS
状态机、连接池、DKIM 签名，以及 MTA-STS 策略执行。

它提供三种投递策略（中继到现有 SMTP 主机、交给本地 MTA 如 Postfix/sendmail、
或自行解析 MX 记录直接投递），你可以选择与现有邮件运维方式匹配的一种，也可以
让 Perfect-SMTP 本身充当最终的 MTA。

> 6.0.0 是对基于 libcurl 的 Perfect-SMTP 5.x 的完整重写。如果你使用过旧版
> `EMail`/`SMTPClient`/`Recipient` API，请参阅英文 README 的
> [Migrating from 5.x](README.md#migrating-from-5x) 一节和用户指南中的
> [从旧版 Perfect-SMTP 迁移](Documentation/user-guide.md#migrating-from-the-old-perfect-smtp)
> 一节——这不是一次可以直接替换的升级。旧代码保留在 `legacy` 分支和 `5.0.0` 标签上。

## 功能特性

- **基于 SwiftNIO 手写的 SMTP 客户端**——自有的 STARTTLS 升级流程，对注入/降级
  攻击有精确到字节的缓冲区安全保证；带断路器的连接池；支持 PIPELINING。
- **DKIM 签名**（RFC 6376）——支持 RSA-SHA256 和 Ed25519-SHA256（RFC 8463），
  包括双重签名；自动对安全敏感的头字段做 oversigning（过度签名）；内置
  DMARC 对齐检查（lint）。
- **三种投递策略**——`RelayTransport`（ESP 或现有 SMTP 中继）、
  `LocalMTATransport`（交给同一主机上的 `sendmail`/Postfix）、
  `DirectMXTransport`（自行解析 MX 记录直接投递，带自己的重试队列和断路器）。
- **MTA-STS**（RFC 8461）——针对直连 MX 投递的策略发现、缓存与执行，并默认
  启用机会性（opportunistic）STARTTLS。
- **SASL 认证**——`PLAIN`、`LOGIN`、`XOAUTH2`（Gmail/Workspace 必需，
  Microsoft 365 也在逐步要求使用）。
- **送达率相关头字段**——`List-Unsubscribe`/`List-Unsubscribe-Post`
  （RFC 8058）、`Precedence`、`Auto-Submitted`——自 2025 年 11 月起
  Gmail 和 Yahoo 已对批量发件人强制要求这些头字段。
- **面向批量/列表服务器场景**——有并发上限的批量 `send`，以及基于
  `AsyncSequence` 的流式 `send`，可以在不将全部收件人一次性载入内存的情况下
  发送给数百万收件人。
- **结构化的投递结果**——每次发送都会为每个收件人返回一个结果（已送达、
  已排队重试、永久失败、已过期、结果不明确，或传输层失败），而不是单一的
  成功/失败标志。

除下面的基础用法之外的内容，请参阅**[完整用户指南](Documentation/user-guide.md)**。

## 环境要求

- Swift 6.2 或更高版本（`swift-tools-version: 6.2`，Swift 6 语言模式）
- macOS 12 或更高版本，或 Linux（CI 覆盖 Ubuntu 24.04 上的 Swift 6.2 与 6.4）

不支持 iOS/tvOS/watchOS：这是一个服务端软件包。

## 安装

在你的 `Package.swift` 中添加依赖：

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "6.0.0")
```

并依赖 `PerfectSMTP` 产品（它重新导出了 `PerfectSMTPCore`；只有在你需要不经
发送、单独完成消息组合/签名时才需要直接依赖 `PerfectSMTPCore`）：

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "PerfectSMTP", package: "Perfect-SMTP"),
    ]
)
```

## 快速开始

通过一个现有的 SMTP 中继（企业自有 MTA，或 SendGrid/Postmark/SES 等 ESP）
发送一封邮件：

```swift
import NIOPosix
import PerfectSMTP

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

let transport = RelayTransport(
    config: RelayConfig(
        host: "smtp.example.com",
        port: 587,
        tls: .startTLS,
        auth: .plain(username: "postmaster@example.com", password: "secret")
    ),
    group: group
)
let mailer = SMTPMailer(transport: transport)

var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
message.to = [EmailAddress(address: "user@dest.com")]
message.subject = "Hello from Perfect-SMTP"
message.textBody = "Hi there!"

let results = try await mailer.send(message, envelopeFrom: .address("ops@example.com"))
for result in results {
    print(result.recipient, result.outcome)
}

await transport.shutdown()
try await group.shutdownGracefully()
```

**安全默认值：** 所有 TLS 连接都会完整校验证书；`.startTLS` 在服务器未提供
STARTTLS 时直接失败，绝不降级为明文；当 `tls: .none` 且配置了认证信息时，
`send` 会抛出 `RelayTransportError.authenticationRequiresTLS`，除非显式设置
`allowsAuthenticationWithoutTLS: true`。详见英文 README 的
[Security defaults](README.md#security-defaults) 一节。

基础用法就是这些。关于 DKIM 签名、直连 MX 投递、认证方式、批量发送以及
送达率相关头字段，请参阅**[用户指南](Documentation/user-guide.md)**。

## 测试

```
swift test
```

全部测试都无需任何外部服务、环境变量、互联网或 DNS 即可运行——需要套接字的
测试（STARTTLS 握手、完整的 DirectMX 投递、DNS 解析器、MTA-STS 获取）都针对
`127.0.0.1` 上的进程内伪服务器运行。CI 在 Linux 和 macOS 上以 debug 和
release 两种配置、带 `-warnings-as-errors` 运行全部测试。

说明：原始重写计划文档（`Documentation/swift6-nio-rewrite-plan.md` §4.1/§5）
中描述了另一层通过 `SMTP_TESTS=1` 环境变量启用、针对 MailHog/smtp4dev CI
服务容器的实时集成测试。这一层从未被实现——`Tests/` 目录下没有任何地方引用
这个环境变量，也没有任何需要手动开启的测试。如果你需要针对真实 SMTP 服务器
做验证，可以自行将 `RelayTransport` 或 `DirectMXTransport` 指向本地的
MailHog/smtp4dev 实例；参见用户指南中的
[测试你的集成](Documentation/user-guide.md#testing-your-integration)一节。

## 许可证

Apache License 2.0——详见 [LICENSE](LICENSE)。

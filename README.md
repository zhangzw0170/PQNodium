# PQNodium

**Post-Quantum Decentralized Messaging**

> PQ = Post-Quantum | Nodium = Node + Sodium (NaCl)

## 概述 / Overview

PQNodium 是一个后量子安全的去中心化即时通讯协议，基于 Rust 构建。它使用 libp2p、QUIC 和后量子密码学取代中心化服务器模型，实现真正的 P2P 通信。

PQNodium is a post-quantum secure, decentralized messaging protocol built with Rust. It replaces the centralized server model with a pure P2P architecture using libp2p, QUIC, and post-quantum cryptography.

### 核心特性 / Key Features

- 🔐 **后量子加密 / PQC by Default**: ML-KEM 密钥交换，ML-DSA 身份签名。
- 🌐 **纯 P2P / Pure P2P**: 无中心服务器，通过 Kademlia DHT 实现 LAN + WAN 通信。
- 🏗️ **Rust 内核 / Rust Core**: 内存安全，零成本抽象。
- 📦 **Tauri 前端 / Tauri Frontend**: 轻量、安全、可设计的用户界面。
- 🔒 **零降级策略 / Zero Downgrade**: 加密不可用时拒绝通信，绝不明文传输。

## 快速开始 / Quick Start

```bash
# 构建 / Build
cargo build --release -p pqnodium-cli

# 生成身份 / Generate identity
./target/release/pqnodium-cli generate

# 启动节点 / Start node (TUI)
./target/release/pqnodium-cli start

# 连接对等节点 / Dial a peer
# 在 TUI 中输入: /dial /ip4/<IP>/udp/<PORT>/quic-v1/p2p/<PEER_ID>

# 运行开发模式 / Run dev (Tauri)
cargo tauri dev
```

## 文档 / Documentation

所有文档位于 `doc/` 目录中。 / All documentation is in the `doc/` directory.

| 文档 / Document | 说明 / Description |
|-----------------|-------------------|
| [文档中心 / Doc Hub](./doc/README.md) | 完整文档索引 |
| [项目起源 / Origin](./doc/start/01_origin_and_comparison.md) | 为什么创建 PQNodium |
| [技术方案 / Tech Plan](./doc/start/03_technical_plan.md) | 架构与路线图 |
| [安全策略 / Security](./doc/SECURITY.md) | 漏洞报告 |
| [AI 声明 / AI Declaration](./doc/AI_DECLARATION.md) | AI 工具使用声明 |
| [构建指南 / Build Guide](./doc/build/BUILD.md) | 编译与交叉编译 |

## 目标平台 / Target Platforms

| 平台 / Platform | 架构 / Arch | 状态 / Status |
|-----------------|-------------|--------------|
| Windows | `x86_64-pc-windows-msvc` | ✅ 已验证 / Verified |
| Linux | `x86_64-unknown-linux-gnu` | ✅ 已验证 / Verified |

跨平台 P2P 连接已在 Windows ↔ Ubuntu 24.04 (QUIC 有线直连) 上验证成功。
Cross-platform P2P connectivity verified on Windows ↔ Ubuntu 24.04 (QUIC wired direct).

## 许可 / License

MIT. See [LICENSE](./LICENSE) for details.

---

*PQNodium — 为后量子时代而生的去中心化节点。*
*PQNodium — Decentralized nodes for the post-quantum era.*

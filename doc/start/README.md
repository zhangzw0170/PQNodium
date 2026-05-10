# PQNodium — 项目文档

**Post-Quantum Decentralized Messaging**

> PQ = Post-Quantum | Nodium = Node + Sodium (NaCl) | 后量子时代的去中心化节点

## 文档导航

| 文档 | 内容 |
|------|------|
| [01_origin_and_comparison](./01_origin_and_comparison.md) | 项目起源、ZFeiQ 对比、架构差异 |
| [02_naming](./02_naming.md) | 项目命名释义 |
| [03_technical_plan](./03_technical_plan.md) | 技术方案、加密选型、里程碑规划 |

## 快速了解

PQNodium 是一个**后量子安全的去中心化即时通讯系统**：

- 🔐 **PQ 加密** — ML-KEM + ML-DSA，抗量子计算机攻击
- 🌐 **全场景 P2P** — LAN + WAN，DHT 发现 + QUIC 直连
- 🏗️ **Rust 实现** — 内存安全、零成本抽象
- 🔗 **libp2p 栈** — Kademlia、GossipSub、Relay 开箱即用
- 📡 **混合握手** — X25519 + ML-KEM-768，经典与 PQ 双重保障

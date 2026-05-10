# PQNodium — 命名释义

## PQNodium

**发音**: `/ˌpiːkjuːˈnoʊdiəm/`

### 词源拆解

| 部分 | 含义 |
|------|------|
| **PQ** | Post-Quantum，后量子加密，项目核心卖点 |
| **Node** | 节点，去中心化 P2P 网络的基本单元 |
| **-ium** | 化学元素后缀（如 Sodium/Titanium），暗示项目如同一种基础物质 |

### 隐藏含义

- **Sodium** 致敬 Daniel J. Bernstein 的 **NaCl** 加密库，是现代后量子加密的基础
- **Nodium** ≈ Node + Sodium = "后量子时代的节点"
- 听起来像正经协议/标准，不是玩具项目

### 项目名与模块对应

```
PQNodium
├── pqnodium-core      核心逻辑 (身份、加密、消息)
├── pqnodium-p2p       P2P 网络层 (libp2p、QUIC、Kademlia、GossipSub、Relay)
├── pqnodium-cli       CLI 界面
└── src-tauri/         Tauri v2 桌面应用 (Rust 后端 + React 前端)
```

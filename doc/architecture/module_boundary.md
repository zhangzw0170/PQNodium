# Module Boundaries

## Workspace Layout

```
PQNodium/
├── pqnodium-core/          # 纯 Rust 业务逻辑（无网络、无 UI 依赖）
│   ├── crypto/             #   密码学 trait + adapter（最大模块化，可独立替换）
│   │   ├── traits/         #     纯 trait，零外部依赖              ✅
│   │   ├── hybrid/         #     PQ/T 组合逻辑                    ✅
│   │   ├── backend/pqc/    #     具体 crate adapter               ✅
│   │   └── conformance/    #     统一测试套件                     ⏳ Phase 2
│   ├── identity.rs         #   身份管理（密钥存储、PeerId 生成）    ✅
│   ├── message.rs          #   消息协议（编解码、序列化）           ✅
│   └── state.rs            #   会话状态机                         ✅
├── pqnodium-p2p/           # libp2p 集成（QUIC、Kademlia、GossipSub、Relay） ⏳ Phase 2
├── pqnodium-cli/           # 终端界面                              ⏳ Phase 3
└── src-tauri/              # Tauri v2 应用壳 + React 前端         ⏳ Phase 3b
```

## Dependency Rules

依赖方向严格单向：`cli/tauri → p2p → core`。禁止反向依赖。

```
src-tauri ──→ pqnodium-p2p ──→ pqnodium-core
pqnodium-cli ─→ pqnodium-p2p ──→ pqnodium-core
```

- `pqnodium-core` 不依赖任何网络或 UI crate，可 `no_std`（crypto/network 除外）。非密码学能力（哈希、序列化、I/O）优先使用 `std`，不引入不必要的第三方依赖。
- `pqnodium-p2p` 只依赖 `core` 的 trait 和数据结构，不直接调用 crypto adapter。
- `src-tauri` 和 `pqnodium-cli` 通过 `p2p` 层的公共 API 交互，不跨层访问。

## Crypto Module: Modularity-first

密码学模块是 PQNodium 模块化程度最高的部分。设计目标是：**任何底层 crate 都可以在不影响上层代码的情况下被替换**。

详细设计见 [Crypto API](../api/crypto_api.md)。

关键约束：
- 上层代码只依赖 `traits/` 中定义的 trait，永不直接 `use` 具体 adapter。
- 每个 adapter 文件只封装一个 crate，替换时只改一个文件。
- 所有 adapter 必须通过 `conformance/` 测试套件验证后才能接入。

# PQNodium — 技术方案

## 技术栈选型

| 层 | 技术选型 | 理由 |
|------|---------|------|
| **语言** | Rust | 内存安全、并发、零成本抽象 |
| **网络框架** | libp2p | 成熟 P2P 栈，QUIC/Kademlia/GossipSub 开箱即用 |
| **传输层** | QUIC (quinn) | 0-RTT、内置 TLS 1.3、NAT 穿透友好 |
| **安全层** | Noise + PQC | true hybrid 握手，经典+PQ 双重保障 |
| **身份层** | Ed25519 + ML-DSA-65 | Hybrid 签名，抗量子 + 向后兼容 |
| **密钥交换** | X25519 + ML-KEM-768 | PQ/T hybrid，FIPS 203 标准 |
| **发现层** | Kademlia DHT | 去中心化节点发现 |
| **群组** | MLS (RFC 9420) 或 GossipSub | 前向安全 + 后向安全的群组通信 |
| **消息加密** | ChaCha20-Poly1305 | AEAD，PQ 安全下对称层仍安全 |
| **运行时** | Tokio | Rust 异步事实标准 |
| **前端框架** | Tauri v2 + React + Tailwind | Rust 原生支持、轻量、安全攻击面小 |

## 标准 Library 优先策略

能用标准库就用标准库。第三方 crate 仅在 `std` 无法覆盖时引入：

| 能力 | 方案 |
|------|------|
| 错误类型 | `std::error::Error`；公共 API Error enum 用 `thiserror` 派生 |
| 哈希（非密码学） | `std::collections::hash_map` / `std::hash` |
| 序列化 | 优先 `std::fmt` / 手动解析；仅在跨进程/持久化时引入 `serde` |
| 随机数（非密码学） | `rand` crate；密码学安全随机数由 PQC crate 自带 |
| 文件 I/O | `std::fs` / `std::io` |
| 时间 | `std::time` |
| 线程同步 | `std::sync`（配合 tokio） |

## 推荐 Rust Crate

| 用途 | Crate | 状态 | 可替换性 |
|------|-------|------|---------|
| 网络框架 | `libp2p` + `libp2p-quic` | 稳定 | — |
| QUIC | `quinn` | 稳定 | — |
| ML-KEM (密钥封装) | `ml-kem` (RustCrypto) | FIPS 203，稳定 | adapter 隔离，可替换 |
| ML-DSA (签名) | `crystals-dilithium` | FIPS 204 | adapter 隔离，可替换 |
| X25519 | `x25519-dalek` | 稳定 | 与 ml-kem 组合 Hybrid KEM |
| Noise + PQC | `clatter` | 实验性 | ❌ 未采用，Hybrid KEM 基于 ml-kem + x25519-dalek 自行组合 |
| 群组消息 | `openmls` / `saorsa-mls` | 实验性 | 独立模块，不影响 1:1 |
| 敏感数据清零 | `zeroize` (RustCrypto) | 稳定 | — |
| 序列化（按需） | `serde` + `serde_json` | 稳定 | 仅在跨进程/持久化时引入 |

> **注意**:
> - 标记为"实验性"的 crate 是最大的替换风险点。模块化设计确保它们被隔离在 adapter 层，替换时无需修改上层协议逻辑。
> - `rustpq` 和 `qcomm-core` 的 GitHub 仓库已失效，不采用。Hybrid KEM 基于 `ml-kem` + `x25519-dalek` 自行组合。
> - 详见 [References](../REFERENCE.md)。

## 通信协议栈

```
┌─────────────────────────────────────────┐
│          应用层: 消息/文件/群组           │
├─────────────────────────────────────────┤
│   MLS / 自定义消息协议 (ChaCha20-Poly1305)│
├─────────────────────────────────────────┤
│   Noise Protocol (X25519 + ML-KEM-768)  │
│   ← true hybrid 握手，经典+PQ 双重保障     │
├─────────────────────────────────────────┤
│   QUIC / TLS 1.3 (传输层加密)             │
├─────────────────────────────────────────┤
│   libp2p                                │
│   ├── Kademlia (DHT 发现)               │
│   ├── Identify (节点信息交换)            │
│   ├── AutoNAT (NAT 类型检测)            │
│   ├── Relay v2 (中继回退/服务器)         │
│   ├── DCUtR (打洞直连升级)              │
│   └── GossipSub (群组广播)              │
├─────────────────────────────────────────┤
│   UDP                                   │
└─────────────────────────────────────────┘
```

## 加密方案详情

### 密码学架构: 可插拔加密后端 (Pluggable Crypto)

PQNodium 的密码学层采用**最大模块化**设计。后量子密码学生态仍在快速演进，crate 可能出现 API breaking change、停止维护、甚至算法被发现漏洞。因此每个密码学原语必须可独立替换：

- 上层只依赖 trait，不依赖具体 crate
- 每个 crate 封装在独立 adapter 中，替换只改一个文件
- 统一 conformance test 确保替换后行为一致

详见 [Crypto API](../api/crypto_api.md) 和 [Module Boundaries](../architecture/module_boundary.md)。

#### 1. PQC 后端 (默认)
- **身份签名**: Ed25519 + ML-DSA-65 (Hybrid)
- **密钥交换**: X25519 + ML-KEM-768 (PQ/T hybrid)
- **消息加密**: ChaCha20-Poly1305 (AEAD)
- **适用场景**: 全球通用、抗量子攻击、高安全性

#### 2. 国密后端 (可选插件)
- **身份签名**: SM2 (椭圆曲线签名)
- **密钥交换**: SM2 密钥协商
- **消息加密**: SM4-GCM (AEAD)
- **适用场景**: 国内政企合规、信创替代、等保测评

> **注意**: 国密算法属于经典密码学，不具备抗量子能力。在国密后端中，仍需结合 PQC 算法以满足长期安全需求。

### Fail-Safe: 零降级策略 (Zero Downgrade)

**核心原则**: 当 PQC 后端和国密后端均不可用时，PQNodium **必须拒绝通信**，绝对禁止回退到明文发送。

- **拒绝明文回退**: 如果握手过程中无法协商出加密套件，连接立即终止。
- **启动前检查**: 应用启动时验证加密模块可用性。若 `ml-kem` 或 `sm2` 均未加载成功，应用拒绝启动或提示用户。
- **运行时监控**: 运行时若检测到加密模块崩溃或被卸载，立即切断所有 P2P 连接。

### Hybrid 密钥交换 (PQ/T)

```
共享密钥 = KDF(
    X25519_ECDH(ephemeral_pub, ephemeral_priv) ||
    ML-KEM-768_Decapsulate(ciphertext, priv_key)
)
```

- 即使 ML-KEM 被攻破，X25519 仍提供安全保障
- 即使 X25519 被量子计算机破解，ML-KEM 仍提供安全保障
- 符合 `draft-ietf-tls-ecdhe-mlkem` 规范

### Hybrid 身份签名

```
身份验证 = Ed25519_verify(sig_ed, msg, pk_ed)
        && ML-DSA-65_verify(sig_pq, msg, pk_pq)
```

### 数据参数

| 算法 | 公钥大小 | 私钥大小 | 密文/签名 |
|------|---------|---------|----------|
| Ed25519 | 32 B | 32 B | 64 B |
| ML-DSA-65 | 4032 B | 2400 B | 3309 B |
| X25519 | 32 B | 32 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B |

### Harvest-Now-Decrypt-Later 防护

攻击者现在可以截获加密流量存储，等量子计算机成熟后解密。
PQNodium 使用 ML-KEM 确保即使量子计算机出现，历史消息也无法被解密。

## 平台策略

### 第一阶段: x86_64 桌面双端

| 目标 | 架构 | 构建三元组 |
|------|------|-----------|
| Windows | x86_64 | `x86_64-pc-windows-msvc` |
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |

**选择理由**:
- 同一架构 → 无字节序/ABI 差异，二进制协议直接互通
- 跨 OS 验证 → Win ↔ Linux 互传成功 = 协议设计正确
- PQC 性能 → x86_64 上 ML-KEM-768 KeyGen ~11μs，无压力
- libp2p → 两个平台都是 first-class，QUIC 完整支持
- 开发效率 → CI 两条 target，简单干净

### 第二阶段 (之后)

| 平台 | 状态 | 备注 |
|------|------|------|
| macOS (Apple Silicon) | 待评估 | 需 `aarch64-apple-darwin` 交叉编译 |
| Android | Phase 2 | 需处理 Doze/后台限制、NAT 策略 |
| iOS | 最后考虑 | 后台限制极严，P2P 适配成本高 |
| Web/WASM | ❌ 不推荐 | QUIC 不可用，PQC 在 WASM 太慢 |

## UI 框架选型

### 选定: Tauri v2

```
架构: pqnodium-core (Rust lib) ──(Tauri IPC)──▶ React/TS 前端 (待搭建)
                                              Tailwind CSS + shadcn/ui
```

**选择理由**:
1. **Rust 原生集成**: PQNodium 核心 (PQC 加密 + libp2p) 是 Rust 实现，Tauri 允许直接调用，无需 FFI 桥接
2. **安全基因**: Tauri 利用系统 WebView，默认安全策略严格，无 Node.js 暴露，攻击面远小于 Electron
3. **资源效率**: 内存占用 ~10-50MB，打包体积 5-15MB，适合常驻后台的聊天应用
4. **开发效率**: 前端可用 React + TypeScript + Tailwind + shadcn/ui，社区现成组件多
5. **协议兼容**: MLS 加密聊天在 Tauri v2 中可行（参考 Signal Protocol 设计）

### 其他框架对比

| 框架 | 状态 (2026.5) | 为什么没选 |
|------|--------------|-----------|
| **Electron** | 成熟但笨重 | 内存占用高 (100-300MB)，捆绑 Chromium 攻击面大，Rust 集成需要 napi-rs 桥接 |
| **Qt (C++/QML)** | 稳定 | C++ 与 Rust 核心集成痛苦 (cxx-qt/手动 FFI)，GPL 许可需注意 |
| **GPUI** | Zed 1.0 (2026-04-29) | 文档在 Zed 源码中，学习曲线陡，生态不如 Tauri |
| **Dioxus** | 0.7.6 → 0.8 即将发布 | 生态小于 Tauri，且即将 breaking changes |
| **iced** | 0.14 活跃 | 设计感上限不如 Tauri，需大量自定义 |
| **egui** | 活跃 | 即时模式 UI 性能差，难做设计感 |
| **Slint** | 1.x 稳定 | DSL 学习曲线，生态较小 |
| **Makepad** | 1.0 发布 | Shader DSL 学习曲线陡，生态最小 |

### Tauri vs Electron vs Qt (x86_64 Win/Linux)

| 维度 | **Tauri v2** | **Electron** | **Qt (C++/QML)** |
|------|-------------|-------------|-----------------|
| **架构** | 系统 WebView + Rust 后端 | 捆绑 Chromium + Node.js | C++ 原生 / Rust binding 间接 |
| **Rust 集成** | **原生一等支持** | 需要 `napi-rs` / FFI 桥接 | 需要 `cxx-qt` / 手动 FFI |
| **内存占用** | **极低** (~10-50MB 起步) | 极高 (100-300MB 起步) | 低 (原生水平) |
| **打包体积** | **小** (5-15MB) | 大 (100MB+) | 中等 (依赖静态/动态库) |
| **安全性** | **高** (攻击面小，无 Node.js) | 中 (Chromium 漏洞风险) | 高 (C++ 内存安全需手动) |
| **开发体验** | Web 技术 (React/Vue/Svelte) | Web 技术 (React/Vue) | QML 或 C++ Widgets |
| **许可协议** | Apache-2.0 / MIT | MIT | GPL / 商业 (开源需注意) |

## 项目里程碑

### Phase 0-1: 首个里程碑 (Win ↔ Linux 互通)

| 阶段 | 目标 | 关键交付 |
|------|------|---------|
| **Phase 0** | 项目骨架 | Cargo workspace, CI (`x86_64-pc-windows-msvc` + `x86_64-unknown-linux-gnu`), 基本目录结构 | ✅ Done |
| **Phase 1** | 核心层 | 身份系统 (Ed25519+ML-DSA)、加密 (X25519+ML-KEM)、消息协议 | ✅ Done |
| **Phase 2** | P2P 层 | libp2p 集成、Kademlia DHT、QUIC 传输 | ✅ Done |
| **Phase 3** | CLI | 终端交互，登录/发消息/发现节点 | ✅ Done |
| **Phase 3b** | Tauri 壳 | Tauri v2 项目初始化、IPC stub | ✅ Done (前端未搭建) |

**✅ 首个里程碑交付**:
- [x] PQC Hybrid 握手完成 (X25519 + ML-KEM-768)
- [x] 加密消息互发 (ChaCha20-Poly1305)
- [x] Windows 节点 ↔ Linux 节点 直连成功（QUIC 有线直连已验证）
- [ ] 文件互传
- [x] Kademlia DHT 发现彼此（已跨节点验证）

**✅ 第二个里程碑交付 (Phase 4)**:
- [x] SwarmBuilder 迁移 + Relay Client 传输层
- [x] AutoNAT NAT 类型检测
- [x] Relay v2 Client（手动指定 relay 地址）
- [x] Relay v2 Server（可选，`--relay-server`）
- [x] DCUtR 打洞直连升级
- [x] CLI/TUI 集成（`--relay`, `--relay-server`, `/relay`, `/nat`）
- [x] CI 全绿（Lint, Test, Build, Audit）

### Phase 4+: 后续扩展

| 阶段 | 目标 | 关键交付 |
|------|------|---------|
| **Phase 4** | NAT 穿透 | Relay fallback、UDP hole punching | ✅ Done |
| **Phase 5** | 群组 | GossipSub 或 MLS 群组通信 |
| **Phase 6** | Tauri GUI | 完整聊天界面、主题、多语言 |
| **Phase 7** | 扩展平台 | macOS / Android (按需) |

## 安全考量

### 已考虑

- [x] Post-Quantum 密钥交换 (ML-KEM-768)
- [x] Hybrid 签名身份验证 (Ed25519 + ML-DSA-65)
- [x] 前向保密 (临时密钥)
- [x] Harvest-Now-Decrypt-Later 防护
- [x] QUIC 传输层加密 (TLS 1.3)

### 待解决

- [ ] MITM 防御 (需要 out-of-band 身份验证，如指纹比对)
- [ ] 抗 DoS / Sybil 攻击
- [ ] 消息去重 / Replay 防护
- [ ] 密钥轮换策略
- [ ] 群组消息的 Post-Compromise Security

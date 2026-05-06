# References / 参考文献

PQNodium 设计与实现中引用的标准、协议、crate 及资料。文献本体不同步到 git，仅记录链接。

> **能用标准库就用标准库**。第三方 crate 仅在标准库无法覆盖时引入（PQC 密码学、P2P 网络、异步运行时、GUI 框架），且优先选择有活跃维护和清晰仓库的。

---

## Standards & RFCs

| 编号 | 标题 | 在项目中的用途 |
|------|------|--------------|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | 默认 PQC 密钥交换算法 |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard (ML-DSA) | 默认 PQC 身份签名算法 |
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols | 消息加密 (AEAD) |
| RFC 7748 | Elliptic Curves for Security (X25519) | 经典 ECDH 密钥交换 |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) | 经典身份签名 |
| RFC 9420 | The Messaging Layer Security (MLS) Protocol | 群组通信（Phase 5+） |
| RFC 9000 / 9001 / 9002 | QUIC | 传输层协议 |
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | QUIC 内置传输层加密 |
| draft-ietf-tls-ecdhe-mlkem | Hybrid ECDHE + ML-KEM Key Exchange for TLS | Hybrid 密钥交换规范参考 |
| GM/T 0002-2012 | SM4 分组密码算法 | 国密后端对称加密 |
| GM/T 0003-2012 | SM2 椭圆曲线公钥密码算法 | 国密后端签名与密钥交换 |
| GM/T 0004-2012 | SM3 密码杂凑算法 | 国密后端哈希 |

## Protocols & Specifications

| 名称 | 说明 | 在项目中的用途 |
|------|------|--------------|
| Noise Protocol Framework | 轻量级握手协议框架 | PQ hybrid 安全层握手 |
| Kademlia DHT | 分布式哈希表 | 去中心化节点发现 |
| GossipSub | 基于 gossip 的发布/订阅 | 群组消息广播 |
| libp2p Circuit Relay v2 | 中继协议 | NAT 穿透 fallback |
| mDNS | 多播 DNS | 局域网节点发现 |

## Rust Crates

### 标准库优先

以下能力由 `std` 直接覆盖，不引入第三方 crate：

| 能力 | 标准库模块 |
|------|-----------|
| 错误类型 | `std::error::Error` + `#[derive(thiserror::Error)]` 仅在公共 API 的 Error enum 上使用 |
| 哈希 | `std::collections::hash_map` / `std::hash`（非密码学用途） |
| 序列化 | 优先 `std::fmt::Debug` / 自定义 `impl Display`；仅在需要跨进程/持久化格式时引入 `serde` |
| 随机数 | `std::rand`（非密码学用途）；密码学安全随机数由 PQC crate 自带 |
| 异步基础 | `std::future::Future` / `std::async_iter` |
| 文件 I/O | `std::fs` / `std::io` |
| 网络 | `std::net`（基础）；复杂 P2P 由 `libp2p` 提供 |
| 时间 | `std::time` |
| 线程 | `std::thread` / `std::sync`（配合 tokio） |

### 网络与运行时

| Crate | 用途 | 仓库 |
|-------|------|------|
| `libp2p` + `libp2p-quic` | P2P 网络框架 | <https://github.com/libp2p/rust-libp2p> |
| `quinn` | QUIC 传输实现 | <https://github.com/quinn-rs/quinn> |
| `tokio` | 异步运行时 | <https://github.com/tokio-rs/tokio> |
| `tauri` (v2) | 桌面应用框架 | <https://github.com/tauri-apps/tauri> |

### 密码学

| Crate | 用途 | 仓库 | 备注 |
|-------|------|------|------|
| `ml-kem` | ML-KEM (FIPS 203) | <https://github.com/RustCrypto/KEMs> | RustCrypto 维护，稳定 |
| `crystals-dilithium` | ML-DSA (FIPS 204) | <https://github.com/Quantum-Blockchains/dilithium> | crates.io 存在 |
| `clatter` | Noise + PQC hybrid 握手 | <https://github.com/jmlepisto/clatter> | 实验性，需评估 |
| `openmls` | MLS 协议实现 | <https://github.com/openmls/openmls> | Phase 5+ 群组用 |
| `saorsa-mls` | MLS + PQC 签名 | <https://github.com/dirvine/saorsa-mls> | 实验性，需评估 |
| `zeroize` | 敏感数据安全清零 | <https://github.com/RustCrypto/utils> | RustCrypto 维护 |

> **注意**: `rustpq`（Hybrid KEM）和 `qcomm-core`（PQ Triple Ratchet）的 GitHub 仓库已失效（crates.io 仍可拉取），实现时需重新评估是否采用，或基于 `ml-kem` + `x25519-dalek` 自行组合。

### 序列化（按需引入）

仅在需要跨进程或持久化格式时引入，否则用 `std::fmt` / 手动解析：

| Crate | 用途 | 仓库 |
|-------|------|------|
| `serde` + `serde_json` | JSON 序列化 | <https://serde.rs/> |
| `postcard` | `no_std` 紧凑二进制序列化（备选） | <https://github.com/jamesmunns/postcard> |

### 交叉编译

| 工具 | 用途 | 仓库 |
|------|------|------|
| `cross` | 交叉编译 | <https://github.com/cross-rs/cross> |

## Reference Projects

| 项目 | 说明 | 链接 |
|------|------|------|
| Signal Protocol | Double Ratchet / 群组加密参考 | <https://signal.org/docs/> |
| Tox | 去中心化即时通讯参考架构 | <https://tox.chat/> |
| ZFeiQ | 前置项目，教训来源 | <https://github.com/zhangzw0170/ZFeiQ> |

## Resources

| 名称 | 说明 | 链接 |
|------|------|------|
| NIST PQC Standardization | NIST 后量子密码标准化 | <https://csrc.nist.gov/projects/post-quantum-cryptography> |
| IETF TLS Working Group | TLS 协议演进（含 PQC 集成） | <https://datatracker.ietf.org/wg/tls/about/> |
| libp2p Documentation | libp2p 文档 | <https://docs.rs/libp2p/latest/libp2p/> |
| Tauri Documentation | Tauri v2 官方文档 | <https://v2.tauri.app/> |
| RustCrypto Project | RustCrypto 组织（ml-kem / zeroize 等） | <https://github.com/RustCrypto> |

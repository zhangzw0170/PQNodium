# Crypto API

## Design Philosophy: Maximum Modularity

PQNodium 的密码学层以**高度模块化**为设计核心。后量子密码学生态仍在快速演进（crate API 变更、新标准出台、已有方案被攻破），因此每个密码学原语必须可独立替换，不能让单个 crate 的变更波及整个系统。

**设计原则**:
- 每个密码学原语（KEM、签名、AEAD、Hash）通过 trait 抽象，上层代码只依赖 trait，不依赖具体实现。
- 具体 crate（`ml-kem`、`crystals-dilithium`、`clatter` 等）封装在独立的 adapter 模块中，可热替换。
- 非密码学能力（哈希、序列化、I/O 等）优先使用 `std`，不引入不必要的第三方依赖。
- 当某个实验性 crate 不再维护或 API breaking change 时，只需重写 adapter，无需改动协议层或应用层。
- 所有 adapter 必须通过统一的 conformance test 套件（向量测试 + 交叉验证），确保替换后行为一致。

## Module Layout

```
pqnodium-core/src/crypto/
├── traits/           # 纯 trait 定义（无外部依赖）
│   ├── kem.rs        # KeyEncapsulation trait        ✅ Done
│   ├── sign.rs       # Signer trait                  ✅ Done
│   └── aead.rs       # AeadCipher trait              ✅ Done
├── hybrid/           # 组合逻辑（PQ/T hybrid、hybrid signature）
│   ├── hybrid_kem.rs # 组合两个 KEM 的结果             ✅ Done
│   └── hybrid_sig.rs # 组合两个签名验证               ✅ Done
├── backend/          # 具体 crate 的 adapter 实现
│   └── pqc/          # PQC 后端（默认）
│       ├── ml_kem.rs # ml-kem crate adapter           ✅ Done
│       ├── ml_dsa.rs # crystals-dilithium adapter     ✅ Done
│       ├── ed25519.rs                                  ✅ Done
│       ├── x25519.rs                                   ✅ Done
│       └── chacha20.rs                                 ✅ Done
└── conformance/      # 统一测试套件                     ⏳ Phase 2
```

## Pluggable Backends

| 后端 | Feature Gate | 状态 | 说明 |
|------|-------------|------|------|
| **PQC (默认)** | — | ✅ Done | ML-KEM-768 + ML-DSA-65 + X25519 + Ed25519 + ChaCha20-Poly1305 |
| **国密** | `crypto-sm` | ⏳ Future | SM2 + SM3 + SM4-GCM，需配合 PQC 后端使用 |
| **未来** | `crypto-xxx` | ⏳ Future | 如 NIST 后续标准、新 PQ KEM 竞赛胜出者 |

## Key Interfaces

```rust
/// 密钥封装 (KEM) — ML-KEM-768, X25519, SM2 等均实现此 trait
trait KeyEncapsulation: Send + Sync {
    type PublicKey: AsRef<[u8]>;
    type SecretKey: Zeroize;
    type Ciphertext: AsRef<[u8]>;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(pk: &Self::PublicKey, rng: &mut impl CryptoRngCore) -> (Self::Ciphertext, SharedSecret);
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<SharedSecret>;
}

/// 签名 — ML-DSA-65, Ed25519, SM2 等均实现此 trait
trait Signer: Send + Sync {
    type PublicKey: AsRef<[u8]>;
    type SecretKey: Zeroize;
    type Signature: AsRef<[u8]>;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::PublicKey, Self::SecretKey);
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}

/// AEAD 对称加密 — ChaCha20-Poly1305, SM4-GCM 等均实现此 trait
trait AeadCipher: Send + Sync {
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
}

/// Hybrid KEM: 组合两个独立 KEM 的共享密钥
/// SharedSecret = KDF(kem1_ss || kem2_ss)
fn hybrid_kem<K1: KeyEncapsulation, K2: KeyEncapsulation>(...) -> SharedSecret;

/// Hybrid Signature: 两个签名都必须验证通过
fn hybrid_verify<S1: Signer, S2: Signer>(...) -> bool;
```

## Adapter 替换流程

当需要替换某个底层 crate（如 `ml-kem` → 新 NIST 标准）时：

1. 在 `backend/pqc/` 下新建 adapter 文件，实现对应 trait
2. 在 `conformance/` 中确认通过所有向量测试
3. 在 `Cargo.toml` 中切换依赖，编译通过即完成
4. 无需修改 `hybrid/`、`traits/` 或上层任何代码

## Crate 依赖隔离

| adapter 依赖的 crate | 被替换时影响范围 | 备注 |
|----------------------|----------------|------|
| `ml-kem` | 仅 `backend/pqc/ml_kem.rs` | RustCrypto 维护，FIPS 203，稳定 |
| `crystals-dilithium` | 仅 `backend/pqc/ml_dsa.rs` | FIPS 204，稳定 |
| `x25519-dalek` | 仅 `backend/pqc/x25519.rs` | 稳定 |
| `ed25519-dalek` | 仅 `backend/pqc/ed25519.rs` | 稳定 |
| `chacha20poly1305` | 仅 `backend/pqc/chacha20.rs` | 稳定 |
| `openmls` / `saorsa-mls` | 仅群组消息模块，不影响 1:1 通信 | 实验性，Phase 5+ |

> `rustpq` 和 `qcomm-core` 已失效，不采用。`clatter` 亦未采用，Hybrid KEM 基于 `ml-kem` + `x25519-dalek` 自行组合。详见 [References](../REFERENCE.md)。

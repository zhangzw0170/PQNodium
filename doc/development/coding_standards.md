# Coding Standards

## General

- **Language**: Rust (Edition 2021+)
- **Format**: `cargo fmt` (rustfmt)
- **Lint**: `cargo clippy -- -D warnings`
- **Docs**: `///` doc comments required for all public items.

## Std-First

能用标准库就用标准库，第三方 crate 仅在 `std` 无法覆盖时引入：

| 能力 | 方案 |
|------|------|
| 错误类型 | `std::error::Error`；公共 API Error enum 用 `thiserror` 派生 |
| 哈希（非密码学） | `std::collections::hash_map` / `std::hash` |
| 序列化 | 优先 `std::fmt` / 手动解析；仅在跨进程/持久化时引入 `serde` |
| 随机数（非密码学） | `rand` crate；密码学安全随机数由 PQC crate 自带 |
| 文件 I/O | `std::fs` / `std::io` |
| 时间 | `std::time` |
| 线程同步 | `std::sync`（配合 tokio） |

## Architecture

- **Core Logic**: `pqnodium-core` 不依赖网络或 UI crate，可 `no_std`（crypto/network 除外）。
- **Dependency Direction**: 严格单向 `cli/tauri → p2p → core`，禁止反向依赖。
- **Async**: 使用 `tokio`。
- **Error Handling**: 分层策略：
  - 简单模块：`std::error::Error` + `impl Display`
  - 库的公共 Error enum：`thiserror` 派生
  - 二进制 crate：`anyhow`
  - 禁止 `unwrap()` / `expect()` 在库代码中出现（测试除外）
  - 禁止静默吞错

## Security

- **Zeroization**: 所有敏感数据（密钥、签名）必须实现 `zeroize` trait。
- **Constant Time**: MAC 和签名验证必须使用常量时间比较。
- **No Custom Crypto**: 禁止手写密码学实现，必须使用经过审计的 crate。
- **Zero Downgrade**: 加密不可用时拒绝通信，禁止回退明文。

## File & Code Organization

- 文件不超过 800 行，函数不超过 50 行
- 按功能/领域组织模块，不按类型
- 公共 API 与内部实现分离：`pub` 严格控制可见性

## Testing

- Conformance test 是密码学模块的首个交付物
- CI gate: `cargo fmt --check` + `cargo clippy` + `cargo test` 全部通过才能合并
- 目标覆盖率 80%+

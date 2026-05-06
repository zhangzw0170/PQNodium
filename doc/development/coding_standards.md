# Coding Standards

## General
- **Language**: Rust (Edition 2021+)
- **Format**: `cargo fmt` (rustfmt)
- **Lint**: `cargo clippy -- -D warnings`
- **Docs**: `///` doc comments required for all public items.

## Architecture
- **Core Logic**: Must be `no_std` compatible where possible (except crypto/network).
- **Async**: Use `tokio`.
- **Error Handling**: Use `thiserror` for libraries, `anyhow` for applications.

## Security
- **Zeroization**: Use `zeroize` trait for sensitive data (keys, secrets).
- **Constant Time**: Use constant-time comparisons for MACs/Signatures.

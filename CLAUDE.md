# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PQNodium is a post-quantum secure, decentralized messaging protocol built with Rust. It replaces centralized servers with a pure P2P architecture using libp2p, QUIC, and post-quantum cryptography (ML-KEM-768 key exchange, ML-DSA-65 signatures). Currently in Phase 0 (project skeleton / planning) — no source code yet, only documentation and design specs.

**Language convention**: Documentation and commit messages are bilingual (Chinese primary, English secondary). Code, variable names, and technical terms are in English.

## Architecture

### Workspace Crates

```
pqnodium-core    — Pure Rust business logic (Crypto, Protocol, State). Aim for no_std compat where possible.
pqnodium-p2p     — libp2p integration: QUIC transport, Kademlia DHT, GossipSub, Relay.
pqnodium-cli     — Terminal interface (tokio-based async).
src-tauri/       — Tauri v2 app shell + IPC handlers. Frontend at src-tauri/web/ (React + TypeScript + Tailwind).
```

### Protocol Stack (bottom-up)

```
UDP → QUIC (quinn, TLS 1.3) → Noise PQ Hybrid (X25519 + ML-KEM-768) → MLS/Custom messaging (ChaCha20-Poly1305) → App layer (JSON-RPC over IPC for Tauri)
```

### Crypto Design

- **Pluggable backends**: PQC backend (default) and SM backend (optional, for China compliance). Zero-downgrade policy — if neither crypto backend loads, the app refuses to start.
- **Hybrid key exchange**: `KDF(X25519_ECDH || ML-KEM-768_Decapsulate)` — both must succeed.
- **Hybrid signatures**: Both Ed25519 and ML-DSA-65 must verify.
- **Key crates**: `ml-kem` (RustCrypto, FIPS 203), `crystals-dilithium` (FIPS 204). Never roll custom crypto implementations.
- **Std-first**: Prefer `std` over third-party crates for error types, hashing (non-crypto), serialization (use `serde` only when cross-process/persistence is needed), I/O, and time.

## Build Commands

```bash
# Core CLI (once workspace exists)
cargo build --release -p pqnodium-cli

# Tauri frontend
cd src-tauri/web && npm install && cd ../.. && cargo tauri dev

# Cross-compile Win → Linux
cross build --target x86_64-unknown-linux-gnu --release

# Targets: x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu
```

### Tooling

```bash
cargo fmt                          # Format
cargo clippy -- -D warnings        # Lint
cargo test                         # Tests
cargo audit                        # Dependency vulnerability scan
```

## Coding Standards

- **Rust edition**: 2021+
- **Async runtime**: tokio
- **Error handling**: `std::error::Error` for simple cases; `thiserror` derive for library Error enums; `anyhow` only in binary crates.
- **Security**: `zeroize` trait on all sensitive data (keys, secrets). Constant-time comparisons for MACs/signatures.
- **Docs**: `///` doc comments required on all public items.
- **Aim for `no_std`** compatibility in core logic (except crypto/network modules).

## Git Workflow

- **`dev`** is the active development branch. All PRs target `dev`.
- **`main`** is stable releases, merged from `dev` during releases.
- **Conventional Commits**: `type(scope): description` (e.g., `feat(pqc): add ML-KEM key generation`)
- **Squash merge** to keep history clean.

## Documentation Structure

All docs are in `doc/` with bilingual content. Key files:

- `doc/start/03_technical_plan.md` — Full architecture, tech stack rationale, milestones
- `doc/architecture/` — Protocol stack, module boundaries, threat model (many are stubs pending Phase 1)
- `doc/REFERENCE.md` — All referenced standards, RFCs, crates, and resources
- `doc/build/BUILD.md` — Build prerequisites and instructions
- `doc/development/coding_standards.md` — Detailed coding rules
- `doc/SECURITY.md` — Vulnerability reporting policy
- `doc/currentRisk/` — Per-phase security risk analysis

## Development Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Workspace skeleton, CI, directory structure | Current |
| 1 | Core crypto (identity, encryption, message protocol) | Pending |
| 2 | P2P layer (libp2p, Kademlia, QUIC) | Pending |
| 3 | CLI interface | Pending |
| 3b | Tauri shell + frontend scaffold | Pending |
| 4+ | NAT traversal, groups, full GUI, mobile | Future |

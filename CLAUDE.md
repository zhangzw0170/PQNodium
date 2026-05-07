# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PQNodium is a post-quantum secure, decentralized messaging protocol built with Rust. It replaces centralized servers with a pure P2P architecture using libp2p (QUIC + TCP), and post-quantum cryptography (ML-KEM-768 key exchange, ML-DSA-65 signatures). Phases 0–3 are complete — workspace skeleton, core crypto layer, P2P networking, and CLI interface are all implemented and tested.

**Language convention**: Documentation and commit messages are bilingual (Chinese primary, English secondary). Code, variable names, and technical terms are in English.

## Architecture

### Workspace Crates

```
pqnodium-core    — Pure Rust business logic (Crypto, Protocol, State). Aim for no_std compat where possible.
pqnodium-p2p     — libp2p integration: QUIC + TCP transport, Kademlia DHT, Identify, Ping.
pqnodium-cli     — Terminal interface (tokio + clap).
pqnodium-app    — Tauri v2 app shell (src-tauri/). IPC stubs only; frontend not yet scaffolded.
```

### Protocol Stack (bottom-up)

```
UDP/TCP → QUIC (quinn) or TCP+Noise+Yamux → Identify → Ping → Kademlia DHT → App layer
```

### Crypto Design

- **Pluggable backends**: PQC backend (default) and SM backend (optional, for China compliance). Zero-downgrade policy — if neither crypto backend loads, the app refuses to start.
- **Hybrid key exchange**: `KDF(X25519_ECDH || ML-KEM-768_Decapsulate)` — both must succeed.
- **Hybrid signatures**: Both Ed25519 and ML-DSA-65 must verify.
- **Key crates**: `ml-kem` (RustCrypto, FIPS 203), `crystals-dilithium` (FIPS 204). Never roll custom crypto implementations.
- **Std-first**: Prefer `std` over third-party crates for error types, hashing (non-crypto), serialization (use `serde` only when cross-process/persistence is needed), I/O, and time.

## Build Commands

```bash
# Core CLI
cargo build --release -p pqnodium-cli

# Tauri app (frontend not yet scaffolded)
cargo tauri dev

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
- **Error handling**: `std::error::Error` for simple cases; `thiserror` derive for library Error enums; `anyhow` only in binary crates. No `unwrap()` in library code.
- **Security**: `zeroize` trait on all sensitive data (keys, secrets). Constant-time comparisons for MACs/signatures. No custom crypto.
- **Docs**: `///` doc comments required on all public items.
- **Aim for `no_std`** compatibility in core logic (except crypto/network modules).
- **Std-first**: Prefer `std` over third-party crates. See `doc/development/coding_standards.md` for full list.

## Git Workflow

- **`dev`** is the active development branch. All PRs target `dev`.
- **`main`** is stable releases, merged from `dev` during releases.
- **Branch naming**: `feat/<scope>-<desc>`, `fix/<scope>-<desc>`, `hotfix/<desc>`, `docs/<desc>`.
- **Conventional Commits**: `type(scope): description` (e.g., `feat(pqc): add ML-KEM key generation`)
  - Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`
  - Scopes: `pqc`, `crypto`, `identity`, `message`, `network`, `dht`, `cli`, `tauri`, `deps`, `ci`
- **Squash merge** to keep history clean.
- Full details: `doc/development/git_workflow.md`

## Documentation Structure

All docs are in `doc/` with bilingual content. Key files:

- `doc/start/03_technical_plan.md` — Full architecture, tech stack rationale, milestones
- `doc/architecture/` — Protocol stack, module boundaries, threat model
- `doc/REFERENCE.md` — All referenced standards, RFCs, crates, and resources
- `doc/build/BUILD.md` — Build prerequisites and instructions
- `doc/development/coding_standards.md` — Detailed coding rules
- `doc/SECURITY.md` — Vulnerability reporting policy
- `doc/currentRisk/` — Per-phase security risk analysis

## Development Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Workspace skeleton, CI, directory structure | Done |
| 1 | Core crypto (identity, encryption, message protocol) | Done |
| 2 | P2P layer (libp2p, Kademlia, QUIC) | Done |
| 3 | CLI interface | Current |
| 3b | Tauri shell + frontend scaffold | Done (shell only, no frontend) |
| 4+ | NAT traversal, groups, full GUI, mobile | Future |

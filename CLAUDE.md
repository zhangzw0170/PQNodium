# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PQNodium is a post-quantum secure, decentralized messaging protocol built with Rust. It replaces centralized servers with a pure P2P architecture using libp2p (QUIC + TCP), and post-quantum cryptography (ML-KEM-768 key exchange, ML-DSA-65 signatures). Phases 0–8 are complete — workspace skeleton, core crypto layer, P2P networking with NAT traversal, Gossipsub broadcast messaging, structured envelope wire format, message deduplication, CLI interface (ratatui TUI), and Tauri app shell are all implemented and tested.

**Language convention**: Documentation and commit messages are bilingual (Chinese primary, English secondary). Code, variable names, and technical terms are in English.

## Build & Test Commands

```bash
# Build
cargo build --release -p pqnodium-cli          # CLI binary
cargo build --release -p pqnodium-core         # Core library
cargo build --release -p pqnodium-p2p          # P2P library
cargo tauri dev                                 # Tauri app (frontend not yet scaffolded)
cargo tauri build                               # Tauri release build
cross build --target x86_64-unknown-linux-gnu --release  # Cross-compile Win → Linux

# Test
cargo test                                     # All tests
cargo test -p pqnodium-core                    # Core only
cargo test -p pqnodium-p2p                     # P2P only
cargo test -p pqnodium-cli                     # CLI only
cargo test --test eight_node_mesh              # Specific integration test
cargo test hybrid_kem_roundtrip                # Single test by name
cargo test -- --nocapture                      # Show output

# Lint & Format
cargo fmt                                      # Format
cargo clippy -- -D warnings                    # Lint (warnings as errors)
cargo audit                                    # Dependency vulnerability scan
```

Prerequisites: Rust 1.80+, CMake, Node.js 18+ (for Tauri). See `doc/build/BUILD.md` for details.

## Architecture

### Crate Dependency Graph

```
pqnodium-core  ←  pqnodium-p2p  ←  pqnodium-cli
                  (libp2p)        (tokio + clap)
                  pqnodium-core  ←  src-tauri (Tauri v2 app shell)
```

`pqnodium-core` has zero async/network dependencies. `pqnodium-p2p` wraps libp2p behind a `PqNode` API. Both `pqnodium-cli` and `src-tauri` are consumers.

### pqnodium-core: Crypto & Protocol

Four public modules: `crypto`, `identity`, `message`, `state`, plus `envelope` for Gossipsub message wire format.

**Crypto trait hierarchy** — the key architectural pattern:
- `traits/kem.rs`: `KeyEncapsulation` trait (generic over PublicKey/SecretKey)
- `traits/sign.rs`: `Signer` trait
- `traits/aead.rs`: `AeadCipher` trait
- `backend/pqc/`: Concrete implementations (`X25519Kem`, `MlKem768Kem`, `Ed25519Signer`, `MlDsa65Signer`, `ChaCha20Poly1305Cipher`)
- `hybrid/`: Generic `HybridKem<K1, K2>` and `HybridSignature<S1, S2>` that compose any two implementations via the traits

**Hybrid KEM construction**: `HybridKem<X25519Kem, MlKem768Kem>` — shared secret = `SHA-256(classic_ss || pqc_ss)`. Ciphertext is length-prefixed: `[classic_ct_len: u16][classic_ct][pqc_ct]` (total 1122 bytes).

**Identity system** (`identity.rs`): `Identity` holds Ed25519 + ML-DSA-65 keypairs. `PeerId` is `SHA-256("pqnodium-peerid-v1" || ed_pk || ml_pk)`. This is **separate from** libp2p's `PeerId` (derived from Ed25519 transport keypair in `pqnodium-p2p`).

**Handshake state machine** (`state.rs`): `HandshakeSession` implements a 2-round hybrid handshake:
- Round 1 (Initiator → Responder): `[x25519_pk: 32][ml_kem_pk: 1184]` = 1216 bytes
- Round 2 (Responder → Initiator): `[resp_pk: 1216][hybrid_ct: 1122]` = 2338 bytes
- States: `Idle → Initiated → Completed` (initiator) or `Idle → Completed` (responder)
- After completion, `SessionKeys` provides `encrypt`/`decrypt` via ChaCha20Poly1305 with directional keys (`send_key`/`recv_key`) derived via `KDF(ss, "initiator-to-responder")` / `KDF(ss, "responder-to-initiator")` and monotonic nonce counters with u64 overflow protection. Fields are private — use `send_key()`/`recv_key()` accessors.

**Message wire format** (`message.rs`): 8-byte header `[version:1][type:1][reserved:2][payload_len:4 BE]` + `[nonce:12]` + `[ciphertext]`. Types: `HandshakeInit(0x01)`, `HandshakeResponse(0x02)`, `HandshakeComplete(0x03)`, `Data(0x10)`, `Ack(0x11)`.

**Envelope format** (`envelope.rs`): Gossipsub broadcast wire format `[version:1][timestamp_ms:8 LE][sender_id_len:2 BE][sender_id][payload_len:4 BE][payload]`. Provides `content_hash()` (SHA-256) for deduplication.

### pqnodium-p2p: libp2p Integration

Modules: `node` (PqNode), `behaviour` (PqBehaviour), `transport`, `config`, `event`, `error`.

**Transport**: SwarmBuilder with QUIC (quinn) + TCP+Noise+Yamux, relay client transport wrapping. Keypair generated per-node with `Keypair::generate_ed25519()`.

**Behaviour composition** (`PqBehaviour`): `Kademlia<MemoryStore>` + `Identify` + `Ping` + `Gossipsub` + `RelayClient` + `RelayServer` + `AutoNAT` + `DCUtR`. mDNS intentionally excluded (causes stale peer discovery on shared networks). Gossipsub uses signed message authenticity and subscribes to the `pqnodium-v1` topic by default. Relay server always present but disabled (`max_reservations=0`) when not in server mode.

**Event loop**: `PqNode::poll_next()` wraps `Swarm::next()` and maps libp2p swarm events into `PqEvent` enum. `PqNode::run()` provides a callback-based loop. Identify-discovered addresses are auto-added to Kademlia routing table. NAT status changes and relay reservations emit dedicated events.

**Config**: `PqNodeConfig` with builder pattern. Default: bind `0.0.0.0:0/quic-v1`, 4 MiB max message, 128 max connections, 60s Kademlia query timeout.

### pqnodium-cli: Terminal Interface

Two subcommands via clap: `generate` (create identity keypair) and `start` (run P2P node with ratatui TUI). The TUI has a log panel, command input bar (`/id`, `/peers`, `/dial`, `/listeners`, `/relay`, `/nat`, `/help`, `/quit`), and scroll support. CLI flags: `--relay-server` (act as relay), `--relay <addr>` (listen via relay).

**Identity file format**: `[magic: 18 bytes][ed_pk_len: u32 LE][ed_pk][ed_sk_len: u32 LE][ed_sk][ml_pk_len: u32 LE][ml_pk][ml_sk_len: u32 LE][ml_sk][HMAC-SHA256: 32]`. HMAC key = `SHA-256(ed_sk || ml_sk)`. Uses `subtle::ConstantTimeEq` for verification. File permissions set to owner-only (0600 on Unix, ACL on Windows).

### Protocol Stack (bottom-up)

```
UDP/TCP → QUIC (quinn) or TCP+Noise+Yamux
        → Identify → Ping → Kademlia DHT
        → AutoNAT (NAT type detection)
        → Relay v2 Client (relay fallback)
        → Relay v2 Server (optional, public nodes)
        → DCUtR (hole-punching direct upgrade)
        → App layer
```

### Crypto Design

- **Pluggable backends**: PQC backend (default) and SM backend (optional, for China compliance). Zero-downgrade policy — if neither crypto backend loads, the app refuses to start.
- **Hybrid key exchange**: `KDF(X25519_ECDH || ML-KEM-768_Decapsulate)` — both must succeed.
- **Hybrid signatures**: Both Ed25519 and ML-DSA-65 must verify.
- **Key crates**: `ml-kem` (RustCrypto, FIPS 203), `crystals-dilithium` (FIPS 204). Never roll custom crypto implementations.
- **Std-first**: Prefer `std` over third-party crates for error types, hashing (non-crypto), serialization (use `serde` only when cross-process/persistence is needed), I/O, and time.

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
| 3 | CLI interface (ratatui TUI) | Done |
| 3b | Tauri shell + frontend scaffold | Done (shell only, no frontend) |
| 4 | NAT traversal (AutoNAT, Relay v2, DCUtR) | Done |
| 5 | Gossipsub broadcast messaging | Done |
| 6 | Envelope wire format (structured messages) | Done |
| 7 | Gossipsub integration tests (2-node, 3-node) | Done |
| 8 | Message deduplication via content hash | Done |
| 8+ | Encrypted broadcast payloads | Pending research |
| 9+ | Full Tauri GUI (React + TypeScript) | Pending research |
| 10+ | Mobile / multi-platform | Pending research |

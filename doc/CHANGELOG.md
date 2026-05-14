# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-15

### Added
- **Phase 5**: Gossipsub broadcast messaging — signed message authenticity, `pqnodium-v1` topic subscription, `PqNode::publish()` API, TUI `/publish` and plaintext input sends broadcast.
- **Phase 6**: Envelope wire format — structured Gossipsub messages with version byte, timestamp, sender ID, payload. `content_hash()` (SHA-256) for deduplication.
- **Phase 7**: Gossipsub integration tests — 2-node message delivery, 3-node broadcast, subscribe/unsubscribe, publish without subscribers (4 tests).
- **Phase 8**: Message deduplication — content-hash based dedup with LRU eviction (1024 entries, 5-min TTL), automatic pruning of expired entries, transparent dedup in `poll_next()`.
- **Phase 4**: NAT traversal — SwarmBuilder migration, AutoNAT, Relay v2 Client/Server, DCUtR hole-punching.
- CLI args: `--relay <addr>` (listen via relay), `--relay-server` (act as relay node).
- TUI commands: `/relay <addr>`, `/nat`, `/publish` for relay, NAT status, and broadcast control.
- New events: `NatStatus`, `RelayReservation`, `DirectConnectionUpgraded`, `Message` (Gossipsub).
- `max_relay_circuits` config field now passed to relay server (was dead code).
- **Phase 0**: Cargo workspace skeleton with `pqnodium-core`, `pqnodium-p2p`, `pqnodium-cli`.
- **Phase 1**: Core crypto — identity system, hybrid KEM (X25519 + ML-KEM-768), hybrid signatures (Ed25519 + ML-DSA-65), message protocol, session state machine.
- **Phase 2**: P2P layer — libp2p integration with QUIC + TCP dual transport, Kademlia DHT, Identify, Ping.
- **Phase 3**: CLI interface — `generate` and `start` subcommands (clap), identity file serialization, ratatui TUI with log panel, command input, and scroll support.
- **Phase 3b**: Tauri v2 app shell (pqnodium-app) with stub IPC commands.
- IPC rate limiting (30 cmds/sec), input validation, CSP hardening in Tauri app.
- HMAC-SHA256 integrity protection for identity files with constant-time verification.
- Connection limits: max 128 incoming connections.
- 8-node local P2P integration test suite (10 tests).
- Gossipsub integration test suite (4 tests).
- Total: 194 tests passing across all suites.
- CI workflows: lint, test, build, audit.

### Changed
- Removed mDNS from P2P behaviour (caused stale peer discovery on shared networks).
- Added TCP + Noise + Yamux as fallback transport alongside QUIC (QUIC hangs on some Windows configurations).
- TUI plain text input now publishes via Gossipsub broadcast (was no-op before Phase 5).

### Fixed
- **Security audit**: directional key derivation for `SessionKeys` — send/recv keys now derived via `KDF(ss, "initiator-to-responder")` / `KDF(ss, "responder-to-initiator")`, preventing catastrophic nonce reuse in bidirectional communication.
- **Security audit**: ML-DSA-65 signing now uses real public key — `MlDsa65SecretKey` stores both secret and public key bytes (crystals-dilithium requires a `Keypair` for signing).
- **Security audit**: X25519 all-zero shared secret detection — both `encapsulate()` and `decapsulate()` reject degenerate Diffie-Hellman results.
- **Security audit**: X25519 `SecretKey` field privatization — inner `[u8; 32]` now private with `from_bytes()`/`as_bytes()` accessors.
- **Security audit**: Bounded identity file parsing — replaces unsafe direct slice indexing with length-checked closures to prevent panics on crafted/truncated files.
- **Security audit**: Config values wired to actual usage — `max_message_size` passed to Gossipsub behaviour, bootstrap peers added to Kademlia routing table on node creation.
- **Correctness**: `HybridSigPublicKey`/`HybridSignature` `AsRef<[u8]>` now returns actual encoded bytes instead of empty slice.
- **Correctness**: ML-DSA-65 `try_from_slice()` enforces FIPS 204 key sizes (pk=1952 bytes, sk=4032 bytes).
- **Correctness**: `SessionKeys` fields privatized with `send_key()`/`recv_key()` accessors.
- **Correctness**: `Envelope::decode()` now rejects trailing data via `EnvelopeError::TrailingData`.
- `connected_peers` HashMap not cleaned up on peer disconnect (memory leak + stale data).
- `GetClosestPeers` results incorrectly treated as connected peers in `/peers`.
- `listen_on_relay` now validates input contains `/p2p/{peer_id}` and uses Multiaddr builder API.
- Clippy `len_zero` and `needless_borrows` lint failures on Rust 1.95.
- CI build-linux job missing Tauri system dependencies (`libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, etc.).

### Joint Debugging (Phase 3 — 双节点联调)

跨平台双节点联调完成（Windows ↔ Ubuntu 24.04，有线直连 QUIC）：

| 测试项 | 结果 |
|--------|------|
| `cargo test` 远端 (42 tests) | ✅ 全部通过 |
| QUIC over Tailscale (100.x) | ❌ 握手超时 |
| TCP+Noise over Tailscale | ❌ 同样超时 |
| QUIC over 有线直连 (192.168.1.x) | ✅ 连接成功 |
| 双节点 peer connected/discovered | ✅ 双向确认 |
| Kademlia DHT bootstrap | ⚠️ 发现对端但 0 peers |
| 连接稳定性 | ⚠️ 约 5s 后断连 → ✅ 已修复（idle_connection_timeout 从默认 10s 调至 24h） |

**发现的问题及解决：**
1. **Git Bash (MSYS2) 路径转换** — multiaddr `/ip4/...` 被自动转成 Windows 路径，bootstrap 参数静默丢弃。需 `MSYS_NO_PATHCONV=1` 环境变量。
2. **远端 UFW 防火墙** — Ubuntu 默认启用 UFW，只放行 SSH 端口，需手动 `ufw allow 9999/tcp && ufw allow 9999/udp`。
3. **Tailscale 不支持 QUIC** — UDP 流量被限制，直连场景需用有线/局域网。
4. **连接断开** — 首次连接成功后约 5-10s 断连。根因：libp2p 0.55 默认 `idle_connection_timeout=10s`，Ping 子流使用 `ignore_for_keep_alive()` 不计入活跃状态，Identify 交换后无活跃子流导致连接被关闭。修复：设 `idle_connection_timeout=24h`，QUIC 传输层 5s keepalive 保持连接存活。修复后连接稳定 3 分钟以上。

### Planned
- Tauri frontend scaffold (React + TypeScript + Tailwind).
- Auto-relay (automatic relay discovery via Kademlia DHT).
- Encrypted broadcast payloads (Envelope + session key encryption).
- Full GUI.
- Mobile support.

[0.1.0]: https://github.com/PQNodium/PQNodium/releases/tag/v0.1.0

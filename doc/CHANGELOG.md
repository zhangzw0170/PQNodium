# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Phase 4**: NAT traversal — SwarmBuilder migration, AutoNAT, Relay v2 Client/Server, DCUtR hole-punching.
- CLI args: `--relay <addr>` (listen via relay), `--relay-server` (act as relay node).
- TUI commands: `/relay <addr>`, `/nat` for relay and NAT status control.
- New events: `NatStatus`, `RelayReservation`, `DirectConnectionUpgraded`.
- `max_relay_circuits` config field now passed to relay server (was dead code).

### Fixed
- `connected_peers` HashMap not cleaned up on peer disconnect (memory leak + stale data).
- `GetClosestPeers` results incorrectly treated as connected peers in `/peers`.
- `listen_on_relay` now validates input contains `/p2p/{peer_id}` and uses Multiaddr builder API.
- Clippy `len_zero` and `needless_borrows` lint failures on Rust 1.95.
- CI build-linux job missing Tauri system dependencies (`libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, etc.).
- **Phase 0**: Cargo workspace skeleton with `pqnodium-core`, `pqnodium-p2p`, `pqnodium-cli`.
- **Phase 1**: Core crypto — identity system, hybrid KEM (X25519 + ML-KEM-768), hybrid signatures (Ed25519 + ML-DSA-65), message protocol, session state machine.
- **Phase 2**: P2P layer — libp2p integration with QUIC + TCP dual transport, Kademlia DHT, Identify, Ping.
- **Phase 3**: CLI interface — `generate` and `start` subcommands (clap), identity file serialization, ratatui TUI with log panel, command input, and scroll support.
- **Phase 3b**: Tauri v2 app shell (pqnodium-app) with stub IPC commands.
- IPC rate limiting (30 cmds/sec), input validation, CSP hardening in Tauri app.
- HMAC-SHA256 integrity protection for identity files with constant-time verification.
- Connection limits: max 128 incoming connections.
- 8-node local P2P integration test suite (10 tests).
- CI workflows: lint, test, build, audit.

### Changed
- Removed mDNS from P2P behaviour (caused stale peer discovery on shared networks).
- Added TCP + Noise + Yamux as fallback transport alongside QUIC (QUIC hangs on some Windows configurations).

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
- Group messaging.
- Full GUI.
- Mobile support.

## [0.1.0] - YYYY-MM-DD
### Added
- Initial release.

[Unreleased]: https://github.com/PQNodium/PQNodium/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PQNodium/PQNodium/releases/tag/v0.1.0

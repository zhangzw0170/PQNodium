# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Phase 0**: Cargo workspace skeleton with `pqnodium-core`, `pqnodium-p2p`, `pqnodium-cli`.
- **Phase 1**: Core crypto — identity system, hybrid KEM (X25519 + ML-KEM-768), hybrid signatures (Ed25519 + ML-DSA-65), message protocol, session state machine.
- **Phase 2**: P2P layer — libp2p integration with QUIC + TCP dual transport, Kademlia DHT, Identify, Ping.
- **Phase 3**: CLI interface — `generate` and `start` subcommands (clap), identity file serialization, interactive event loop.
- **Phase 3b**: Tauri v2 app shell (pqnodium-app) with stub IPC commands.
- 8-node local P2P integration test suite (10 tests).
- CI workflows: lint, test, build, audit.

### Changed
- Removed mDNS from P2P behaviour (caused stale peer discovery on shared networks).
- Added TCP + Noise + Yamux as fallback transport alongside QUIC (QUIC hangs on some Windows configurations).

### Planned
- Tauri frontend scaffold (React + TypeScript + Tailwind).
- NAT traversal.
- Group messaging.
- Full GUI.
- Mobile support.

## [0.1.0] - YYYY-MM-DD
### Added
- Initial release.

[Unreleased]: https://github.com/PQNodium/PQNodium/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PQNodium/PQNodium/releases/tag/v0.1.0

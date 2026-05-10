# Phase 4 Risk Analysis: NAT Traversal

**Phase**: 4 — NAT Traversal (Relay, AutoNAT, DCUtR)
**Date**: 2026-05-08
**Status**: ✅ Complete

## Scope

为 NAT/防火墙后的节点提供中继回退和打洞直连能力：
- SwarmBuilder 迁移（relay client 需要传输层包装）
- AutoNAT（NAT 类型检测）
- Relay v2 Client（中继回退）
- DCUtR（打洞直连升级）
- Relay v2 Server（可选，公共节点）

## New Risks

| ID | Risk | Severity | Status | Mitigation |
|----|------|----------|--------|------------|
| RISK-501 | SwarmBuilder 迁移破坏传输行为 | HIGH | ✅ Mitigated | 迁移后全量测试通过（42 → 124 tests），含 8-node mesh 集成测试 |
| RISK-502 | `Option<relay::Behaviour>` derive 不支持 | MEDIUM | ✅ Mitigated | 始终包含 relay_server 字段，用 `max_reservations=0, max_circuits=0` 禁用 |
| RISK-503 | DCUtR 对称 NAT 打洞失败 | LOW | ✅ Accepted | 已有 relay 回退；对称 NAT 打洞是已知限制 |
| RISK-504 | Relay server 资源耗尽 | MEDIUM | ✅ Mitigated | 可配置 `max_relay_circuits`（默认 16），`max_incoming_connections`（默认 128） |
| RISK-505 | Relay 地址格式错误导致连接失败 | LOW | ✅ Mitigated | `listen_on_relay()` 方法封装地址构造，错误返回 `PqP2pError` |

## Resolved from Previous Phases

| ID | Risk | Phase | New Status |
|----|------|-------|------------|
| RISK-205 | No Relay/TURN for NAT traversal | 2 | ✅ Mitigated — Relay v2 client + DCUtR implemented |

## Implementation Details

### SwarmBuilder Migration

从手动 `Swarm::new(transport, behaviour, peer_id, config)` 迁移到 `SwarmBuilder` 链：
```rust
SwarmBuilder::with_existing_identity(id_keys)
    .with_tokio()
    .with_tcp(tcp::Config::new().nodelay(true), noise::Config::new, yamux::Config::default)
    .with_quic()
    .with_relay_client(noise::Config::new, yamux::Config::default)
    .with_behaviour(|key, relay_client| PqBehaviour::new(..., relay_client, ...))
    .with_swarm_config(|cfg| { ... })
    .build()
```

### Protocol Stack (Updated)

```
UDP/TCP → QUIC (quinn) or TCP+Noise+Yamux
        → Identify → Ping → Kademlia DHT
        → AutoNAT (NAT 类型检测)
        → Relay v2 Client (中继回退)
        → Relay v2 Server (可选，公共节点)
        → DCUtR (打洞直连升级)
        → App layer
```

### Key Decisions

1. **Relay server always included**: `#[derive(NetworkBehaviour)]` 不支持 `Option<T>` 字段，因此 relay_server 始终存在但可通过配置禁用（`max_reservations=0, max_circuits=0`）。
2. **No auto-relay**: 当前版本需要手动指定 relay 地址（`--relay` CLI 参数或 `/relay` TUI 命令）。自动发现 relay 留作未来增强。
3. **DCUtR requires relay**: DCUtR 仅对通过 relay 建立的连接生效，不影响直连。

## Test Results

- `cargo test`: 124 passed (all suites)
- `cargo clippy -- -D warnings`: clean (local + CI Rust 1.95)
- 8-node mesh integration tests: 10/10 passed
- CI: all 4 jobs (Lint, Test, Build, Audit) green

## Code Review Findings (post-commit audit)

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| H1 | HIGH | `connected_peers` not cleaned on `ConnectionClosed` | Added `self.connected_peers.remove()` |
| H2 | HIGH | `max_relay_circuits` config field never used | Passed to `relay::Config` constructor |
| H3 | HIGH | TUI unbounded channels without backpressure | Accepted — single TUI instance, 50ms drain cycle |
| H4 | HIGH | Global `OnceLock` for message sender | Accepted — `run_tui` called exactly once |
| M1 | MEDIUM | `RelayReservation { accepted: false }` never emitted | Known limitation — libp2p 0.55 API gap, failure via `OutboundConnectionError` |
| M4 | MEDIUM | `GetClosestPeers` treated routing table as connected | Removed incorrect insertion |
| M5 | MEDIUM | `listen_on_relay` no peer ID validation | Added validation + Multiaddr builder API |

### Accepted Limitations

- **对称 NAT DCUtR 失败**: 已有 relay 回退，对称 NAT 打洞是已知限制
- **Relay reservation 失败无明确事件**: libp2p 0.55 `relay::client::Event` 没有 failed variant
- **No auto-relay**: 需手动指定 relay 地址，自动发现留作未来增强

# PQNodium Security Risk Analysis

This directory contains the security risk analysis for each phase of PQNodium development.

## Index

| Phase | Document | Status |
|-------|----------|--------|
| **Phase 0** | [Project Setup & Risk Identification](./phase0_risk.md) | ✅ Complete |
| **Phase 1** | [Core Crypto Implementation](./phase1_risk.md) | ✅ Complete |
| **Phase 2** | [P2P Network (libp2p + QUIC + TCP)](./phase2_risk.md) | ✅ Complete |
| **Phase 3** | [CLI Interface](./phase3_risk.md) | ✅ Complete |
| **Phase 3b** | [Tauri Shell + Frontend](./phase3b_risk.md) | ✅ Complete |
| **Phase 4** | [NAT Traversal](./phase4_risk.md) | ✅ Complete |
| **Phase 5-8** | [Gossipsub + Envelope + Dedup](./phase5_8_risk.md) | ✅ Complete |

## Priority Remediation Queue

All HIGH and MEDIUM risks have been fixed or accepted:

| ID | Risk | Phase | Status |
|----|------|-------|--------|
| RISK-001 | Dependency supply chain | 0 | ✅ Mitigated — `cargo audit` CI |
| RISK-101 | Transport handshake not using HybridKem | 1 | ✅ Fixed — app-layer handshake uses HybridKem |
| RISK-203 | No identity binding (Ed25519 ↔ ML-DSA-65) | 2 | ✅ Fixed — PeerId binds both keys |
| RISK-201 | Unwrap in transport construction | 2 | ✅ Fixed |
| RISK-202 | No rate limiting on P2P connections | 2 | ✅ Fixed — max 128 incoming |
| RISK-301 | Identity file lacks permission controls | 3 | ✅ Fixed — 0600/ACL |
| RISK-302 | Identity file lacks integrity protection | 3 | ✅ Fixed — HMAC-SHA256 |
| RISK-401 | IPC handlers lack input validation | 3b | ✅ Fixed — `validate_string_input` |
| RISK-402 | No Content Security Policy | 3b | ✅ Fixed — CSP in tauri.conf.json |
| RISK-404 | No IPC rate limiting | 3b | ✅ Fixed — 30 cmds/sec |
| RISK-207 | Connection drops after ~10s (idle timeout) | 2 | ✅ Fixed — 24h idle timeout |
| RISK-801 | Broadcast payloads not encrypted | 5-8 | ⚠️ Accepted — planned for future phase |
| RISK-803 | No Gossipsub publish rate limiting | 5-8 | ⚠️ Accepted — libp2p peer scoring provides partial mitigation |

### Remaining LOW risks (deferred)

| ID | Risk | Phase |
|----|------|-------|
| RISK-106 | Nonce wrap-around protection | 1 |
| RISK-107 | No key rotation mechanism | 1 |
| RISK-109 | No FIPS 203/204 KAT vectors | 1 |
| RISK-206 | DHT bootstrap hardcoded peers | 2 |
| RISK-304 | No secure stdin for passphrase | 3 |
| RISK-305 | Multiaddr bootstrap silently dropped (Git Bash/MSYS2) | 3 |
| RISK-306 | UFW blocks P2P listening port | 3 |
| RISK-403 | System webview exploitation | 3b |
| RISK-405 | Sensitive data exposure to frontend | 3b |
| RISK-802 | Dedup TTL too short (5 min) | 5-8 |
| RISK-805 | LRU dedup eviction under memory pressure | 5-8 |

## How to Use

1.  **Identify**: Before starting a phase, review the relevant risk document.
2.  **Mitigate**: Implement the suggested mitigations during development.
3.  **Review**: Update the risk status after implementation.
4.  **Archive**: Once a phase is complete and risks are mitigated, update the `CHANGELOG.md`.

## Severity Levels

- **Critical**: Immediate blocker. No workaround. Must be fixed before proceeding.
- **High**: Significant vulnerability. Workarounds exist but are painful.
- **Medium**: Moderate risk. Should be addressed in the same phase.
- **Low**: Minor issue or edge case. Addressed when convenient.

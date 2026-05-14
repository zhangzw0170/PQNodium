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
| RISK-102 | SessionKeys reuse same key for both directions | 1 | ✅ Fixed — directional key derivation via KDF(ss, label) |
| RISK-103 | ML-DSA-65 sign uses empty public key | 1 | ✅ Fixed — MlDsa65SecretKey stores both secret and public bytes |
| RISK-104 | X25519 no all-zero shared secret check | 1 | ✅ Fixed — encapsulate/decapsulate reject degenerate results |
| RISK-105 | X25519 SecretKey public field | 1 | ✅ Fixed — private field with from_bytes()/as_bytes() accessors |
| RISK-106 | Nonce wrap-around protection | 1 | ✅ Fixed — u64 overflow check in next_send_nonce/next_recv_nonce |
| RISK-107 | ML-DSA-65 no key length validation | 1 | ✅ Fixed — try_from_slice enforces FIPS 204 sizes |
| RISK-108 | HybridSig AsRef returns empty slice | 1 | ✅ Fixed — pre-computed encoding stored in struct |
| RISK-109 | SessionKeys fields publicly mutable | 1 | ✅ Fixed — private fields with send_key()/recv_key() accessors |
| RISK-110 | Envelope decode accepts trailing data | 6 | ✅ Fixed — EnvelopeError::TrailingData |
| RISK-203 | No identity binding (Ed25519 ↔ ML-DSA-65) | 2 | ✅ Fixed — PeerId binds both keys |
| RISK-201 | Unwrap in transport construction | 2 | ✅ Fixed |
| RISK-202 | No rate limiting on P2P connections | 2 | ✅ Fixed — max 128 incoming |
| RISK-205 | Config values silently discarded | 2 | ✅ Fixed — max_message_size wired to Gossipsub, bootstrap peers to Kademlia |
| RISK-206 | Identity file parsing panics on truncated input | 3 | ✅ Fixed — bounded read_len_field/read_bytes closures |
| RISK-301 | Identity file lacks permission controls | 3 | ✅ Fixed — 0600/ACL |
| RISK-302 | Identity file lacks integrity protection | 3 | ✅ Fixed — HMAC-SHA256 |
| RISK-401 | IPC handlers lack input validation | 3b | ✅ Fixed — `validate_string_input` |
| RISK-402 | No Content Security Policy | 3b | ✅ Fixed — CSP in tauri.conf.json |
| RISK-404 | No IPC rate limiting | 3b | ✅ Fixed — 30 cmds/sec |
| RISK-207 | Connection drops after ~10s (idle timeout) | 2 | ✅ Fixed — 24h idle timeout |
| RISK-801 | Broadcast payloads not encrypted | 5-8 | ⚠️ Accepted — planned for future phase |
| RISK-803 | No Gossipsub publish rate limiting | 5-8 | ⚠️ Accepted — libp2p peer scoring provides partial mitigation |
| RISK-901 | TUI monolith (1304 lines) | 3 | ✅ Fixed — split into 3 modules (max 797 lines) |
| RISK-902 | CI test matrix only covers Windows | CI | ✅ Fixed — ubuntu-latest added to matrix |
| RISK-903 | 20 cargo audit ignores without justification | CI | ✅ Fixed — each ignore has inline comment |

### Remaining LOW risks (deferred)

| ID | Risk | Phase |
|----|------|-------|
| RISK-108 | No key rotation mechanism | 1 |
| RISK-109 | No FIPS 203/204 KAT vectors | 1 |
| RISK-210 | DHT bootstrap hardcoded peers | 2 |
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

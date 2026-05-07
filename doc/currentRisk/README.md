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
| **Phase 4+** | NAT Traversal, Groups, GUI | ⏳ Pending |

## Priority Remediation Queue

All HIGH-severity risks have been fixed:

| ID | Risk | Phase | Status |
|----|------|-------|--------|
| RISK-101 | Transport handshake not using HybridKem | 1 | ✅ Fixed — app-layer handshake uses HybridKem |
| RISK-203 | No identity binding (Ed25519 ↔ ML-DSA-65) | 2 | ✅ Fixed — PeerId binds both keys |
| RISK-301 | Identity file lacks permission controls | 3 | ✅ Fixed — 0600/ACL permissions set |

### Remaining MEDIUM risks

| ID | Risk | Phase |
|----|------|-------|
| RISK-202 | No rate limiting on P2P connections | 2 |
| RISK-302 | Identity file lacks integrity protection | 3 |
| RISK-401/402/404 | Tauri IPC validation, CSP, rate limiting | 3b |

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

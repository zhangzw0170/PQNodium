# PQNodium Security Risk Analysis

This directory contains the security risk analysis for each phase of PQNodium development.

## Index

| Phase | Document | Status |
|-------|----------|--------|
| **Phase 0** | [Project Setup & Risk Identification](./phase0_risk.md) | ✅ Complete |
| **Phase 1** | Core Crypto Implementation | ✅ Complete |
| **Phase 2** | P2P Network (libp2p + QUIC + TCP) | ✅ Complete |
| **Phase 3** | CLI Interface | ✅ Complete |
| **Phase 3b** | Tauri Shell | ✅ Complete (shell only) |
| **Phase 4+** | NAT Traversal, Groups, GUI | ⏳ Pending |

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

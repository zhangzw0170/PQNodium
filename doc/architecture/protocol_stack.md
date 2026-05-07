# Protocol Stack Design

> 详细的协议栈图和各层技术选型见 [技术方案 — 通信协议栈](../start/03_technical_plan.md#通信协议栈)。

## Implementation Status

| Layer | Protocol | Crate / Implementation | Status |
|-------|----------|----------------------|--------|
| **Crypto Traits** | KEM / Sign / AEAD | `crypto/traits/` | ✅ Done |
| **PQC Backend** | ML-KEM-768, ML-DSA-65, X25519, Ed25519, ChaCha20-Poly1305 | `crypto/backend/pqc/` | ✅ Done |
| **Hybrid Composition** | HybridKem (SHA-256 KDF), HybridSigner | `crypto/hybrid/` | ✅ Done |
| **Identity** | PeerId, Identity, PublicIdentity (hybrid sign/verify) | `identity.rs` | ✅ Done |
| **Message Protocol** | MessageHeader, Message (wire format + AEAD) | `message.rs` | ✅ Done |
| **Session State** | HandshakeSession, SessionKeys (state machine) | `state.rs` | ✅ Done |
| **Transport** | QUIC + TCP (OrTransport) | `pqnodium-p2p/src/transport.rs` | ✅ Done |
| **Discovery** | Kademlia DHT + Identify | `pqnodium-p2p/src/behaviour.rs` | ✅ Done |
| **P2P Node** | PqNode (Swarm wrapper, event loop) | `pqnodium-p2p/src/node.rs` | ✅ Done |
| **CLI** | Interactive terminal (clap + tokio) | `pqnodium-cli/src/main.rs` | ✅ Done |
| **Group** | GossipSub / MLS | — | ⏳ Phase 5+ |
| **Application** | Tauri IPC | `src-tauri/src/main.rs` | ✅ Stub only |

## Layers
1.  **Transport**: QUIC (primary) + TCP+Noise+Yamux (fallback)
2.  **Security**: Noise Protocol (TCP path), TLS 1.3 (QUIC path)
3.  **Network**: Kademlia DHT + Identify
4.  **Messaging**: Custom binary format (Phase 1)
5.  **Application**: Tauri IPC (Phase 3b, stubs only)

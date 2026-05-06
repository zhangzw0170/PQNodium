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
| **Transport** | QUIC (via `quinn` / `libp2p-quic`) | — | ⏳ Phase 2 |
| **Discovery** | Kademlia DHT + mDNS | — | ⏳ Phase 2 |
| **Group** | GossipSub / MLS | — | ⏳ Phase 5+ |
| **Application** | JSON-RPC over IPC (Tauri) | — | ⏳ Phase 3b |

## Layers
1.  **Transport**: QUIC (via `quinn` / `libp2p-quic`)
2.  **Security**: Noise Protocol (Hybrid X25519 + ML-KEM-768)
3.  **Network**: Kademlia DHT + mDNS
4.  **Messaging**: Custom binary format or MLS
5.  **Application**: JSON-RPC over IPC (Tauri)

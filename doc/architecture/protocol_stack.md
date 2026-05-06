# Protocol Stack Design

*Stub: To be filled during Phase 1.*

## Layers
1.  **Transport**: QUIC (via `quinn` / `libp2p-quic`)
2.  **Security**: Noise Protocol (Hybrid X25519 + ML-KEM-768)
3.  **Network**: Kademlia DHT + mDNS
4.  **Messaging**: Custom binary format or MLS
5.  **Application**: JSON-RPC over IPC (Tauri)

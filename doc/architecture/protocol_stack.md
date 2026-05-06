# Protocol Stack Design

*Stub: To be filled during Phase 1.*

> 详细的协议栈图和各层技术选型见 [技术方案 — 通信协议栈](../start/03_technical_plan.md#通信协议栈)。

## Layers
1.  **Transport**: QUIC (via `quinn` / `libp2p-quic`)
2.  **Security**: Noise Protocol (Hybrid X25519 + ML-KEM-768)
3.  **Network**: Kademlia DHT + mDNS
4.  **Messaging**: Custom binary format or MLS
5.  **Application**: JSON-RPC over IPC (Tauri)

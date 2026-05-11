# Threat Model

*Updated: Phase 0-8 complete.*

## Assumptions
- Adversaries may have classical computing capabilities.
- Adversaries may have future quantum computing capabilities ("Harvest Now, Decrypt Later").

## Assets
1.  **Long-term Identity Keys**: Must be kept secret.
2.  **Message Content**: E2EE (1:1 via handshake session keys; broadcast payloads currently unencrypted — future).
3.  **Metadata**: Minimized via P2P routing, but not fully hidden. Gossipsub topic membership visible to participants.

## Attack Vectors
- **MITM**: Mitigated by Hybrid Signatures (Ed25519 + ML-DSA-65) + Out-of-band verification.
- **Replay**: Mitigated by sequence numbers + AEAD (ChaCha20-Poly1305) for 1:1; broadcast dedup via content-hash LRU cache.
- **Broadcast Spam / Flood**: Partially mitigated — Gossipsub has built-in scoring; content-hash dedup prevents exact duplicates. Rate limiting on publish TBD.
- **DoS**: Mitigated by libp2p connection limits (max 128); IPC rate limiting (30/sec); relay circuit limits (default 16).
- **Sybil**: (Future) Trust graphs or PoW.
- **Stale mDNS Peers**: Mitigated — mDNS removed; discovery via Kademlia DHT only.
- **QUIC Handshake Failure**: Mitigated — TCP + Noise + Yamux fallback transport.
- **NAT Blocking**: Mitigated — AutoNAT detection, Relay v2 fallback, DCUtR hole-punching.
- **Broadcast Replay**: Mitigated — content-hash dedup with 5-min TTL LRU cache (1024 entries). Short TTL expiry means older duplicates may pass through.

## Known Limitations (Phase 8)
- Broadcast payloads are **not end-to-end encrypted** — anyone subscribed to `pqnodium-v1` topic can read messages.
- Content-hash dedup only prevents exact duplicates — minor variations bypass dedup.
- No publish rate limiting on Gossipsub — a malicious node can flood the topic.

# Threat Model

*Updated: Phase 0-2 complete. Threat model will be expanded during Phase 4+ when networking hardens.*

## Assumptions
- Adversaries may have classical computing capabilities.
- Adversaries may have future quantum computing capabilities ("Harvest Now, Decrypt Later").

## Assets
1.  **Long-term Identity Keys**: Must be kept secret.
2.  **Message Content**: E2EE.
3.  **Metadata**: Minimized via P2P routing, but not fully hidden.

## Attack Vectors
- **MITM**: Mitigated by Hybrid Signatures (Ed25519 + ML-DSA-65) + Out-of-band verification.
- **Replay**: Mitigated by sequence numbers + AEAD (ChaCha20-Poly1305).
- **DoS**: Mitigated by libp2p connection limits; rate limiting TBD.
- **Sybil**: (Future) Trust graphs or PoW.
- **Stale mDNS Peers**: Mitigated — mDNS removed; discovery via Kademlia DHT only.
- **QUIC Handshake Failure**: Mitigated — TCP + Noise + Yamux fallback transport.

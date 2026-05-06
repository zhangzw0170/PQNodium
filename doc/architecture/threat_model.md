# Threat Model

*Stub: To be expanded during Phase 1.*

## Assumptions
- Adversaries may have classical computing capabilities.
- Adversaries may have future quantum computing capabilities ("Harvest Now, Decrypt Later").

## Assets
1.  **Long-term Identity Keys**: Must be kept secret.
2.  **Message Content**: E2EE.
3.  **Metadata**: Minimized via P2P routing, but not fully hidden.

## Attack Vectors
- **MITM**: Mitigated by Hybrid Signatures + Out-of-band verification.
- **Replay**: Sequence numbers + AEAD.
- **DoS**: Rate limiting at the libp2p level.
- **Sybil**: (Future) Trust graphs or PoW.

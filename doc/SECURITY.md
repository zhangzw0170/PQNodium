# Security Policy

PQNodium is a security-first messaging protocol. We take security vulnerabilities seriously.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, please report them via:
- **Email**: [security@pqnodium.org](mailto:security@pqnodium.org) (placeholder)
- **GitHub Security Advisory**: Use the "Security" tab.

We will acknowledge receipt within 48 hours and provide a detailed response within a week.

## Threat Model

See our detailed [Threat Model](./architecture/threat_model.md).

### Current Security Focus
- **Post-Quantum Cryptography**: ML-KEM for key exchange, ML-DSA for signatures.
- **Transport Security**: QUIC (TLS 1.3).
- **Forward Secrecy**: Ephemeral keys used for every session.
- **Harvest-Now-Decrypt-Later Protection**: PQC prevents future quantum decryption of current traffic.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| < 0.1.0 | ❌ Development only |

## Security Reviews

We conduct internal security audits for every major release. External audits are planned for Phase 5.

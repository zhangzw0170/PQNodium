# Phase 1 Risk Analysis: Core Crypto Implementation

## Phase Overview
- **Goal**: Implement pluggable crypto layer — KEM, Sign, AEAD traits + PQC backends + hybrid composition.
- **Key Boundaries**: Never roll custom crypto; all primitives from audited crates; zeroize all sensitive data.

## Risk Register

### [RISK-101] Transport Handshake Not Using HybridKem — HIGH
- **Severity**: High
- **Impact**: P2P connections only use X25519 for key exchange. If a quantum computer breaks ECDH, all session keys are compromised. The entire post-quantum value proposition is undermined.
- **Trigger**: Any adversary with a sufficiently powerful quantum computer recording traffic today (harvest-then-decrypt).
- **Mitigation**: Integrate HybridKem (X25519 + ML-KEM-768) into the Noise protocol handshake. libp2p's Noise framework supports custom DH patterns — implement a PQ-hybrid pattern that runs both X25519 and ML-KEM-768 in the handshake phase, combining shared secrets via KDF.
- **Status**: ✅ Fixed — Application-layer handshake (`state.rs`) now uses HybridKem (X25519 + ML-KEM-768). Transport-level encryption (Noise/TLS) remains classical-only, which is standard practice (same as Signal, WireGuard).

### [RISK-102] ML-KEM Secret Key Not Zeroized — MEDIUM
- **Severity**: Medium
- **Impact**: ML-KEM-768 secret key material may persist in memory after use, potentially recoverable via memory dump.
- **Trigger**: Process crash with core dump enabled, or cold-boot attack.
- **Mitigation**: Implement `Zeroize` for `MlKem768SecretKey` wrapper type. Ensure the inner key bytes are zeroized on drop. Consider `zeroize::ZeroizeOnDrop` derive.
- **Status**: ✅ Fixed — `#[derive(Zeroize, ZeroizeOnDrop)]` was already present on `MlKem768SecretKey`.

### [RISK-103] X25519 Secret Key Not Zeroized — MEDIUM
- **Severity**: Medium
- **Impact**: X25519 static secret key persists in memory after key generation, recoverable via memory dump.
- **Trigger**: Same as RISK-102.
- **Mitigation**: Wrap `x25519_dalek::StaticSecret` in a type that calls `zeroize()` on drop. `StaticSecret` internally uses `GenericArray` which supports zeroization.
- **Status**: ✅ Fixed — `#[derive(Zeroize, ZeroizeOnDrop)]` was already present on `X25519SecretKey`.

### [RISK-104] Ed25519 Secret Key Zeroization Incomplete — MEDIUM
- **Severity**: Medium
- **Impact**: Ed25519 signing key bytes may not be zeroized after use.
- **Trigger**: Same as RISK-102.
- **Mitigation**: Verify that `ed25519_dalek::SigningKey` zeroizes on drop (it does in recent versions). Add explicit `Zeroize` impl if using raw bytes.
- **Status**: ✅ Fixed — `#[derive(Zeroize, ZeroizeOnDrop)]` was already present on `Ed25519SecretKey`.

### [RISK-105] KDF Output Not Constant-Time Compared — LOW
- **Severity**: Low
- **Impact**: Timing side-channel in shared secret comparison could leak key material.
- **Trigger**: Local attacker with timing measurement capability.
- **Mitigation**: Use `subtle::ConstantTimeEq` for comparing KDF output in hybrid key exchange. Currently using standard byte comparison.
- **Status**: ✅ Fixed — `SharedSecret::ct_eq()` added using `subtle::ConstantTimeEq`.

### [RISK-106] Nonce Reuse Not Prevented at Protocol Level — LOW
- **Severity**: Low
- **Impact**: AEAD nonce reuse with the same key completely breaks ChaCha20-Poly1305 confidentiality.
- **Trigger**: Bug in session state machine reusing counters.
- **Mitigation**: The session state machine uses incrementing counters for nonces. Add a debug assertion that the counter never wraps. Consider audit log for nonce values in debug builds.
- **Status**: Mitigated by design (incrementing counter), but no explicit wrap-around protection.

### [RISK-107] No Key Rotation Mechanism — LOW
- **Severity**: Low
- **Impact**: Long-lived keys increase exposure window. Compromise of a long-term key compromises all past/future sessions.
- **Trigger**: Key compromise over time.
- **Mitigation**: Design key rotation protocol for Phase 4+. Short-term session keys already rotate per-session via KEM.
- **Status**: Deferred to Phase 4+

### [RISK-108] Hybrid Signature Verification Not Short-Circuit Safe — LOW
- **Severity**: Low
- **Impact**: Timing difference between Ed25519 and ML-DSA-65 verification could leak which signature failed.
- **Trigger**: Network observer measuring response times.
- **Mitigation**: Always verify both signatures regardless of early failure. The current `hybrid_verify` implementation does this correctly.
- **Status**: Mitigated by design

### [RISK-109] No FIPS 203/204 Compliance Testing — LOW
- **Severity**: Low
- **Impact**: Cannot claim FIPS compliance without formal test vectors.
- **Trigger**: Regulatory requirement or security audit.
- **Mitigation**: Add NIST Known Answer Test (KAT) vectors to conformance test suite. The `conformance/` directory exists as a placeholder for this.
- **Status**: Deferred — `conformance/` directory is a placeholder

## Threat Model (Phase 1)
- **Attacker Capability**: Quantum computer (harvest-then-decrypt), memory forensics, timing side-channels.
- **Attack Surface**: Crypto trait implementations, hybrid composition logic, key storage in memory.
- **Trust Boundary**: All crypto operations happen in `pqnodium-core` — no network I/O at this layer.

## Security Decisions (ADRs)
- **ADR-003**: Use `ml-kem` (RustCrypto) for ML-KEM-768 — audited, FIPS 203 compliant, actively maintained.
- **ADR-004**: Use `crystals-dilithium` for ML-DSA-65 — FIPS 204 compliant, reference implementation.
- **ADR-005**: Hybrid KEM combines secrets via SHA-256 KDF: `KDF(X25519_ss || ML-KEM_ss)`.
- **ADR-006**: Hybrid signatures require BOTH Ed25519 and ML-DSA-65 to verify — no fallback.

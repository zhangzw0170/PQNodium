# Phase 3 Risk Analysis: CLI Interface

## Phase Overview
- **Goal**: Interactive terminal interface for node management — identity generation, peer discovery, messaging.
- **Key Boundaries**: CLI is a binary crate using `pqnodium-p2p` as a library. No network-facing API beyond what p2p already exposes.

## Risk Register

### [RISK-301] Identity File Lacks Permission Controls — HIGH
- **Severity**: High
- **Impact**: The serialized identity (containing secret keys for Ed25519, ML-DSA-65, X25519, ML-KEM-768) is written to disk with default file permissions. Any process running under the same user can read/modify/replace the identity file, leading to full key compromise.
- **Trigger**: Malware on the user's machine, or another user on a shared system.
- **Mitigation**: Set file permissions to owner-read-only (0600) on Unix, or use Windows ACLs to restrict access. Verify permissions on load. Add integrity protection (see RISK-302).
- **Status**: ✅ Fixed — `set_owner_only_permissions()` sets 0600 on Unix, restricts ACL on Windows. `warn_if_permissions_too_open()` warns on load.

### [RISK-302] Identity File Lacks Integrity Protection — MEDIUM
- **Severity**: Medium
- **Impact**: An attacker with file system access can tamper with the identity file (replace public keys, modify key material) without detection.
- **Trigger**: File system access (local malware, shared system).
- **Mitigation**: Compute HMAC-SHA256 over the serialized identity using a key derived from a user passphrase or the machine's TPM. Verify HMAC on load before deserializing.
- **Status**: ✅ Fixed — HMAC-SHA256 integrity check using key derived from secret keys (SHA-256(ed_sk || ml_sk)). Wire format: `[magic][key_data][HMAC:32]`. Constant-time verification via `subtle::ConstantTimeEq`.

### [RISK-303] Sensitive Data May Leak in Logs — LOW
- **Severity**: Low
- **Impact**: Debug logging could include key material, peer IDs, or message content.
- **Trigger**: Debug builds with tracing enabled, log files accessible to unauthorized parties.
- **Mitigation**: Audit all `tracing::debug!` / `tracing::info!` calls to ensure no secret material is logged. Use `tracing` level filters to suppress sensitive output in release builds. Consider a dedicated sensitive-data redaction layer.
- **Status**: ✅ Fixed — Plaintext message content removed from `info!` logging. Only message byte count is logged.

### [RISK-304] No Secure Memory Handling for CLI Input — LOW
- **Severity**: Low
- **Impact**: Passphrases entered on the command line may appear in shell history or process listings.
- **Trigger**: User enters passphrase as CLI argument instead of via stdin prompt.
- **Mitigation**: Never accept passphrases as command-line arguments. Use `rpassword` or similar crate for secure stdin input. Clear passphrase from memory immediately after use.
- **Status**: Deferred — no passphrase feature yet, but should be enforced when added

## Threat Model (Phase 3)
- **Attacker Capability**: Local user on shared system, malware with file system access, shoulder surfing.
- **Attack Surface**: Identity file on disk, CLI argument parsing, terminal I/O, log files.
- **Trust Boundary**: Local filesystem and terminal are partially trusted (single-user assumed, but not guaranteed).

## Security Decisions (ADRs)
- **ADR-010**: Identity serialization uses `bincode` for compact binary format. No encryption at rest (pending RISK-302 mitigation).

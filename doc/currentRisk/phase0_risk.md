# Phase 0 Risk Analysis: Project Setup & Architecture

## Phase Overview
- **Goal**: Establish Cargo workspace, CI, and project structure.
- **Key Boundaries**: Workspace separation, dependency pinning, CI security.

## Known Risks

### [RISK-001] Dependency Supply Chain
- **Severity**: High
- **Impact**: Malicious or vulnerable crates could compromise the entire project.
- **Trigger**: Adding unmaintained or low-reputation crates.
- **Mitigation**: Use `cargo-audit`, pin dependencies in `Cargo.lock`, review new deps.
- **Status**: ✅ Mitigated — `audit.yml` CI workflow runs `cargo audit` on every push.

### [RISK-002] Insecure CI Pipeline
- **Severity**: Medium
- **Impact**: Compromised CI could inject malicious code into releases.
- **Trigger**: Poor CI configuration, exposed secrets.
- **Mitigation**: Use GitHub Actions best practices, limit permissions, scan for secrets.
- **Status**: ✅ Mitigated — CI workflows (`lint.yml`, `test.yml`, `build.yml`) follow standard GitHub Actions practices with minimal permissions.

### [RISK-003] Lack of Crypto Review
- **Severity**: Critical
- **Impact**: Implementation of PQC algorithms might have subtle bugs.
- **Trigger**: Implementing ML-KEM/ML-DSA from scratch instead of using audited crates.
- **Mitigation**: Rely on `ml-kem` (RustCrypto) and `crystals-dilithium`. Do NOT roll our own crypto.
- **Status**: Mitigated by design choice.

## Threat Model
- **Attacker Capability**: Software supply chain, CI compromise.
- **Attack Surface**: `Cargo.toml` dependencies, GitHub Actions workflows.

## Security Decisions (ADRs)
- **ADR-001**: Use audited PQC crates (`ml-kem`, `crystals-dilithium`) instead of custom implementations.
- **ADR-002**: Use Tauri for UI to minimize attack surface compared to Electron.

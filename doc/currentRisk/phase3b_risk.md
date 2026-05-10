# Phase 3b Risk Analysis: Tauri Shell + Frontend Scaffold

## Phase Overview
- **Goal**: Tauri v2 app shell with IPC handlers bridging to `pqnodium-p2p`. Frontend scaffold with React + TypeScript + Tailwind.
- **Key Boundaries**: Tauri IPC is the only attack surface between frontend (untrusted) and backend (trusted). All sensitive operations happen in Rust.

## Risk Register

### [RISK-401] IPC Handlers Lack Input Validation — MEDIUM
- **Severity**: Medium
- **Impact**: Malicious or malformed IPC commands from the frontend (or injected via XSS) could cause unexpected behavior in the Rust backend — including panic, resource exhaustion, or unauthorized operations.
- **Trigger**: XSS in the webview, or a compromised frontend build.
- **Mitigation**: Validate all IPC inputs at the Rust boundary before processing. Use strongly-typed IPC commands (Tauri v2 commands with typed parameters). Reject unknown commands early.
- **Status**: ✅ Fixed — `validate_string_input()` function enforces length bounds on all string inputs.

### [RISK-402] No Content Security Policy (CSP) — MEDIUM
- **Severity**: Medium
- **Impact**: Without CSP, the webview is vulnerable to XSS attacks that could execute arbitrary JavaScript, potentially sending malicious IPC commands to the Rust backend.
- **Trigger**: XSS via injected content, compromised CDN resource, or man-in-the-middle on HTTP resources.
- **Mitigation**: Configure strict CSP headers in Tauri's webview: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`. Disable remote resource loading in development.
- **Status**: ✅ Fixed — CSP configured in `tauri.conf.json`: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ipc: http://ipc.localhost`

### [RISK-403] WebView Version and Exploitation Risk — LOW
- **Severity**: Low
- **Impact**: The system webview (WebView2 on Windows, WebKit on macOS/Linux) may have known vulnerabilities.
- **Trigger**: User running outdated OS with unpatched webview.
- **Mitigation**: Tauri v2 uses the system webview which is auto-updated via OS updates. Document minimum supported OS versions. Monitor WebView2/WebKit security advisories.
- **Status**: Accepted — standard Tauri risk, mitigated by OS updates

### [RISK-404] No IPC Rate Limiting — MEDIUM
- **Severity**: Medium
- **Impact**: The frontend (or an XSS payload) could flood the IPC channel with commands, exhausting backend resources or causing DoS.
- **Trigger**: Malicious frontend code, XSS payload.
- **Mitigation**: Implement per-command rate limiting on the Rust IPC handler side. Drop or throttle commands that exceed a configurable threshold.
- **Status**: ✅ Fixed — `RateLimiter` with 30 commands/second limit per window, enforced via `LazyLock<Mutex<RateLimiter>>`.

### [RISK-405] Sensitive Data Exposure to Frontend — LOW
- **Severity**: Low
- **Impact**: Secret key material or plaintext messages could be inadvertently exposed to the frontend JavaScript context, where they are accessible to any script running in the webview.
- **Trigger**: IPC handler returning more data than necessary.
- **Mitigation**: Never send secret key material through IPC. Only send derived public data (PeerId, public keys, message metadata). Sanitize all IPC responses to remove sensitive fields.
- **Status**: ✅ Verified — current implementation follows this principle; no secret key material is exposed through IPC

## Threat Model (Phase 3b)
- **Attacker Capability**: XSS in webview, compromised frontend, malicious IPC commands, outdated system webview.
- **Attack Surface**: Tauri IPC boundary, webview content loading, CSP configuration.
- **Trust Boundary**: Frontend (JavaScript) is **untrusted**. Rust backend is **trusted**. IPC is the security boundary.

## Security Decisions (ADRs)
- **ADR-011**: Tauri v2 chosen over Electron for minimal attack surface — no bundled Node.js, no Chromium binary.
- **ADR-012**: All crypto and P2P operations remain in Rust. Frontend only receives sanitized, non-sensitive data via IPC.

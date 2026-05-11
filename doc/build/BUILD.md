# Build Guide

## Prerequisites

<!-- AUTO-GENERATED:from:Cargo.toml -->
| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.80+ (edition 2021) | Core language (install via [rustup](https://rustup.rs/)) |
| CMake | Latest | Required for some native dependencies |
| Node.js | 18+ | Required for Tauri frontend build (Phase 3b+) |
| `cross` | Latest | Cross-compilation (optional) |
<!-- /AUTO-GENERATED -->

## Targets

PQNodium targets `x86_64` architecture for Windows and Linux.

| Target | OS | Command |
|--------|----|---------|
| Windows | x86_64-pc-windows-msvc | `cargo build --target x86_64-pc-windows-msvc` |
| Linux | x86_64-unknown-linux-gnu | `cross build --target x86_64-unknown-linux-gnu` |

## Building

<!-- AUTO-GENERATED:from:Cargo.toml -->
### Available Build Commands

| Command | Description |
|---------|-------------|
| `cargo build --release -p pqnodium-cli` | Build CLI binary (release) |
| `cargo build --release -p pqnodium-core` | Build core library (release) |
| `cargo build --release -p pqnodium-p2p` | Build P2P library (release) |
| `cargo tauri dev` | Run Tauri app in dev mode |
| `cargo tauri build` | Build Tauri app (release) |
| `cross build --target x86_64-unknown-linux-gnu --release` | Cross-compile for Linux |
<!-- /AUTO-GENERATED -->

### Testing

| Command | Description |
|---------|-------------|
| `cargo test` | Run all tests (193 tests across all suites) |
| `cargo test -p pqnodium-core` | Core crypto tests only |
| `cargo test -p pqnodium-p2p` | P2P layer tests only |
| `cargo test -p pqnodium-cli` | CLI tests only |
| `cargo test --test eight_node_mesh` | 8-node mesh integration tests (10 tests) |
| `cargo test --test gossipsub_messaging` | Gossipsub messaging tests (4 tests) |
| `cargo test -- --nocapture` | Show test output |

### Lint & Format

| Command | Description |
|---------|-------------|
| `cargo fmt` | Format code |
| `cargo clippy -- -D warnings` | Lint (warnings as errors) |
| `cargo audit` | Dependency vulnerability scan |

### Tauri App

```bash
# Frontend not yet scaffolded (React + TypeScript + Tailwind planned)
# Build and run Tauri app
cargo tauri dev

# Or build release binary
cargo tauri build
# Output: target/release/pqnodium-app
```

## Cross-Compilation

See [Cross-Compilation Guide](./cross_compile.md).

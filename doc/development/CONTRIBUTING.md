# Contributing to PQNodium

Thank you for your interest in contributing!

## Development Environment Setup

1. Install [Rust 1.80+](https://rustup.rs/) via rustup
2. Install [CMake](https://cmake.org/) (required for native dependencies)
3. Clone and build:
   ```bash
   git clone https://github.com/zhangzw0170/PQNodium.git
   cd PQNodium
   cargo build --workspace
   ```

## Development Workflow

1. **Fork** the repository and create your branch from `dev`.
2. **Code** following our [Coding Standards](./coding_standards.md).
3. **Test** your changes. Ensure `cargo test` passes.
4. **Commit** with clear, descriptive messages (see [Git Workflow](./git_workflow.md)).
5. **Push** to your fork and open a Pull Request against the `dev` branch.

<!-- AUTO-GENERATED:from:Cargo.toml -->
## Available Commands

| Command | Description |
|---------|-------------|
| `cargo build --workspace` | Build all crates |
| `cargo build --release -p pqnodium-cli` | Build CLI (release) |
| `cargo test` | Run all tests (124 tests) |
| `cargo test -p pqnodium-core` | Run core tests only |
| `cargo test -p pqnodium-p2p` | Run P2P tests only |
| `cargo test -p pqnodium-p2p --test eight_node_mesh` | Run 8-node mesh integration test |
| `cargo fmt` | Format code |
| `cargo fmt --check` | Check formatting (CI gate) |
| `cargo clippy -- -D warnings` | Lint (CI gate) |
| `cargo audit` | Dependency vulnerability scan |
| `cargo tauri dev` | Run Tauri app in dev mode |
| `cargo run -p pqnodium-cli -- generate` | Generate a new identity |
| `cargo run -p pqnodium-cli -- start` | Start P2P node |
<!-- /AUTO-GENERATED -->

## Testing

- **Unit tests**: `#[cfg(test)] mod tests` in each source file
- **Integration tests**: `pqnodium-p2p/tests/eight_node_mesh.rs` (8-node mesh topology)
- **CI gate**: `cargo fmt --check` + `cargo clippy` + `cargo test` all must pass
- **Coverage target**: 80%+

## Windows (Git Bash) Notes

Multiaddr bootstrap addresses (e.g., `/ip4/1.2.3.4/udp/9999/quic-v1/p2p/...`) are silently converted to Windows paths by MSYS2 path conversion. Set this environment variable before running:

```bash
export MSYS_NO_PATHCONV=1
```

## Pull Request Guidelines

- Use the provided [PR Template](./pr_template.md).
- Link any relevant issues.
- Ensure CI passes (lint, build, test).
- Add tests for new features.
- Squash merge to keep history clean.

## Communication

- Open an issue for bugs or feature requests.
- Discuss major architectural changes before implementation.

## Code of Conduct

Be respectful and constructive. PQNodium is committed to a harassment-free environment.

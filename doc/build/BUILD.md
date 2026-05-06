# Build Guide

## Prerequisites

- **Rust**: 1.80+ (install via [rustup](https://rustup.rs/))
- **CMake**: Required for some native dependencies.
- **Node.js**: Required for Tauri frontend build (v18+).

## Targets

PQNodium targets `x86_64` architecture for Windows and Linux.

| Target | OS | Command |
|--------|----|---------|
| Windows | x86_64-pc-windows-msvc | `cargo build --target x86_64-pc-windows-msvc` |
| Linux | x86_64-unknown-linux-gnu | `cargo build --target x86_64-unknown-linux-gnu` |

## Building

### Core (CLI)

```bash
cargo build --release -p pqnodium-cli
```

### Tauri Frontend

```bash
# Install frontend dependencies
cd src-tauri/web
npm install

# Build and run Tauri app
cd ../..
cargo tauri dev
```

## Cross-Compilation

See [Cross-Compilation Guide](./doc/build/cross_compile.md).

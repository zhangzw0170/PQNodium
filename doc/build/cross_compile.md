# Cross-Compilation Guide

## Windows (Host) → Linux (Target)
- Use `cross` or install `gcc-x86-64-linux-gnu`.
- Command: `cross build --target x86_64-unknown-linux-gnu --release`

## Linux (Host) → Windows (Target)
- Install `mingw-w64`.
- Command: `cargo build --target x86_64-pc-windows-gnu --release`

## Dependencies
- Tauri requires WebView2 on Windows and WebKitGTK on Linux.

#!/usr/bin/env pwsh
# PQNodium - check.ps1
# Run fmt, clippy, and tests.

cargo fmt --check
if ($LASTEXITCODE -ne 0) { Write-Error "fmt check failed"; exit 1 }

cargo clippy -- -D warnings
if ($LASTEXITCODE -ne 0) { Write-Error "clippy failed"; exit 1 }

cargo test --workspace

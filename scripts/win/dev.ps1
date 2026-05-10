#!/usr/bin/env pwsh
# PQNodium - dev.ps1
# Build and run in development mode.

param(
    [ValidateSet("cli", "core", "p2p")]
    [string]$Package = "cli"
)

cargo build -p "pqnodium-$Package" && cargo run -p "pqnodium-$Package"

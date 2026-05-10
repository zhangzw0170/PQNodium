#!/usr/bin/env bash
# PQNodium - check.sh
# Run fmt, clippy, and tests.

set -euo pipefail

cargo fmt --check
cargo clippy -- -D warnings
cargo test --workspace

#!/usr/bin/env bash
# PQNodium - dev.sh
# Build and run in development mode.

set -euo pipefail

PACKAGE="${1:-cli}"

case "$PACKAGE" in
    cli|core|p2p) ;;
    *) echo "Usage: ./scripts/dev.sh [cli|core|p2p]"; exit 1 ;;
esac

cargo build -p "pqnodium-$PACKAGE" && cargo run -p "pqnodium-$PACKAGE"

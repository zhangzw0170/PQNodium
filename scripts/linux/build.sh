#!/usr/bin/env bash
# PQNodium - build.sh
# Release build. Usage: ./scripts/build.sh [--release] [--target <triple>]

set -euo pipefail

ARGS=(build -p pqnodium-cli)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) ARGS+=(--release); shift ;;
        --target)  ARGS+=(--target "$2"); shift 2 ;;
        *)         echo "Usage: ./scripts/build.sh [--release] [--target <triple>]"; exit 1 ;;
    esac
done

cargo "${ARGS[@]}"

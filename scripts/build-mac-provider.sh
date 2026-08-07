#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$ROOT_DIR/build"

echo "=== 1. Building Go C-Archive (libctkbridge.a) ==="
cd "$ROOT_DIR"
CGO_ENABLED=1 go build -buildmode=c-archive -o build/libctkbridge.a ./internal/ctkbridge

echo "=== 2. Compiling macOS CryptoTokenKit Provider ==="
clang -fobjc-arc \
    -I"$ROOT_DIR/build" \
    -I"$ROOT_DIR/mac-provider" \
    "$ROOT_DIR/mac-provider"/TokenDriver.m \
    "$ROOT_DIR/mac-provider"/Token.m \
    "$ROOT_DIR/mac-provider"/TokenSession.m \
    "$ROOT_DIR/mac-provider"/main.m \
    "$ROOT_DIR/build/libctkbridge.a" \
    -framework Foundation \
    -framework Security \
    -framework CryptoTokenKit \
    -lresolv \
    -lpthread \
    -o "$ROOT_DIR/build/mac-provider"

echo "=== Build Complete! Executable saved at build/mac-provider ==="

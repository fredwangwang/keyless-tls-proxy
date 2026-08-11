#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIGURATION="${1:-Release}"

echo "=== Building MacTokenApp (configuration: $CONFIGURATION) ==="

xcodegen generate

xcodebuild \
    -project "$ROOT_DIR/MacTokenApp.xcodeproj" \
    -scheme MacTokenApp \
    -configuration "$CONFIGURATION" \
    CONFIGURATION_BUILD_DIR="$ROOT_DIR/build" \
    build

echo "=== Build Complete! App bundle created at build/MacTokenApp.app ==="

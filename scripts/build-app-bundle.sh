#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIGURATION="${1:-Release}"

echo "=== Building KeylessProxy (configuration: $CONFIGURATION) ==="

xcodegen generate

xcodebuild \
    -project "$ROOT_DIR/KeylessProxy.xcodeproj" \
    -scheme KeylessProxy \
    -configuration "$CONFIGURATION" \
    -allowProvisioningUpdates \
    CONFIGURATION_BUILD_DIR="$ROOT_DIR/build" \
    build

echo "=== Build Complete! App bundle created at build/KeylessProxy.app ==="

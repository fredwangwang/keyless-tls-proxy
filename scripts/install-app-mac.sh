#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_BUILD_DIR="$ROOT_DIR/build/KeylessProxy.app"
DEST_APP_DIR="/Applications/KeylessProxy.app"
EXT_PATH="$DEST_APP_DIR/Contents/PlugIns/KeylessProxyExtension.appex"

echo "=== 1. Building App Bundle ==="
"$SCRIPT_DIR/build-app-bundle.sh"

echo "=== 2. Replacing Installation in /Applications ==="
if [ -d "$DEST_APP_DIR" ]; then
    echo "Removing existing installation at $DEST_APP_DIR..."
    rm -rf "$DEST_APP_DIR"
fi

echo "Copying $APP_BUILD_DIR to /Applications/..."
cp -R "$APP_BUILD_DIR" /Applications/

echo "=== 3. Registering App Extension with pluginkit ==="
if [ -d "$EXT_PATH" ]; then
    echo "Registering extension at $EXT_PATH with pluginkit -a..."
    pluginkit -a "$EXT_PATH"
    echo "Enabling extension with pluginkit -e use..."
    pluginkit -e use -i com.fredprx.keylessproxy.app.extension
    echo "Plugin info:"
    pluginkit -m -v -i com.fredprx.keylessproxy.app.extension || true
else
    echo "Error: Extension not found at $EXT_PATH"
    exit 1
fi

echo "=== 4. Syncing Token Configuration ==="
echo "Running KeylessProxy to sync driver configuration..."
/Applications/KeylessProxy.app/Contents/MacOS/KeylessProxy 2>&1 &
APP_PID=$!
sleep 2
kill $APP_PID 2>/dev/null || true

echo "=== Installation Complete! KeylessProxy installed to /Applications/KeylessProxy.app ==="

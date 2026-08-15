#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"

mkdir -p "$BUILD_DIR"

TAG="${1:-}"

echo "=========================================="
echo " Building Release Artifacts"
echo "=========================================="

# 1. Build cert-server for macOS (Universal Binary)
echo ""
echo "=== 1. Building cert-server for macOS (arm64 & amd64) ==="
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o "$BUILD_DIR/cert-server-darwin-arm64" "$ROOT_DIR/cmd/cert-server"
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/cert-server-darwin-amd64" "$ROOT_DIR/cmd/cert-server"
lipo -create -output "$BUILD_DIR/cert-server-mac" "$BUILD_DIR/cert-server-darwin-arm64" "$BUILD_DIR/cert-server-darwin-amd64"
rm -f "$BUILD_DIR/cert-server-darwin-arm64" "$BUILD_DIR/cert-server-darwin-amd64"
echo "Created: $BUILD_DIR/cert-server-mac"

# 2. Build cert-server for Windows
echo ""
echo "=== 2. Building cert-server for Windows (x64) ==="
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$BUILD_DIR/cert-server-windows.exe" "$ROOT_DIR/cmd/cert-server"
echo "Created: $BUILD_DIR/cert-server-windows.exe"

# 3. Build Windows KSP Package (windows-ksp.zip)
echo ""
echo "=== 3. Building Windows KSP binaries ==="
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  CC_WIN="x86_64-w64-mingw32-gcc"
elif command -v gcc >/dev/null 2>&1; then
  CC_WIN="gcc"
else
  echo "Error: MinGW GCC (x86_64-w64-mingw32-gcc) or gcc is required to build Windows KSP DLL."
  exit 1
fi

echo "Building Go c-archive bridge (tpmcertclient.a)..."
CGO_ENABLED=1 CC="$CC_WIN" GOOS=windows GOARCH=amd64 go build -buildmode=c-archive -o "$BUILD_DIR/tpmcertclient.a" "$ROOT_DIR/internal/kspbridge"

echo "Compiling fredprx_ksp.dll..."
"$CC_WIN" -shared -O2 -Wall -I"$ROOT_DIR/ksp" -o "$BUILD_DIR/fredprx_ksp.dll" \
  "$ROOT_DIR/ksp/ksp.c" "$ROOT_DIR/ksp/tpmcert_storage.c" "$BUILD_DIR/tpmcertclient.a" \
  -lbcrypt -lncrypt -lcrypt32 -ladvapi32 -lws2_32 -lsecur32 "$ROOT_DIR/ksp/ksp.def"

echo "Building ksp-register.exe, ksp-install-cert.exe, and ksp-install-ui.exe..."
CGO_ENABLED=1 CC="$CC_WIN" GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/ksp-register.exe" "$ROOT_DIR/cmd/ksp-register"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$BUILD_DIR/ksp-install-cert.exe" "$ROOT_DIR/cmd/ksp-install-cert"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-H windowsgui" -o "$BUILD_DIR/ksp-install-ui.exe" "$ROOT_DIR/cmd/ksp-install-ui"

echo "Creating windows-ksp.zip..."
rm -f "$BUILD_DIR/windows-ksp.zip"
zip -j "$BUILD_DIR/windows-ksp.zip" "$BUILD_DIR/fredprx_ksp.dll" "$BUILD_DIR/ksp-register.exe" "$BUILD_DIR/ksp-install-cert.exe" "$BUILD_DIR/ksp-install-ui.exe"
echo "Created: $BUILD_DIR/windows-ksp.zip"

ISCC_BIN=""
if command -v iscc >/dev/null 2>&1; then
  ISCC_BIN="iscc"
elif command -v ISCC.exe >/dev/null 2>&1; then
  ISCC_BIN="ISCC.exe"
elif [ -f "$LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe" ]; then
  ISCC_BIN="$LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe"
elif [ -f "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" ]; then
  ISCC_BIN="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
fi

if [ -n "$ISCC_BIN" ]; then
  echo "Building Windows Installer (FredProxyKSP-Setup.exe)..."
  "$ISCC_BIN" "/DMyAppVersion=${TAG:-1.0.0}" "/O$BUILD_DIR" "/FFredProxyKSP-Setup" "$ROOT_DIR/installer/windows/ksp-installer.iss" || echo "Warning: Inno Setup build failed."
fi


# 4. Build macOS App & CTK Extension Bundle (KeylessProxy.zip)
echo ""
echo "=== 4. Building macOS KeylessProxy & Extension ==="
"$SCRIPT_DIR/build-app-bundle.sh" Release

echo "Creating KeylessProxy.zip..."
rm -f "$BUILD_DIR/KeylessProxy.zip"
ditto -c -k --keepParent "$BUILD_DIR/KeylessProxy.app" "$BUILD_DIR/KeylessProxy.zip"
echo "Created: $BUILD_DIR/KeylessProxy.zip"

echo ""
echo "=========================================="
echo " Release Artifacts Summary"
echo "=========================================="
RELEASE_FILES=("$BUILD_DIR/cert-server-mac" "$BUILD_DIR/cert-server-windows.exe" "$BUILD_DIR/windows-ksp.zip" "$BUILD_DIR/KeylessProxy.zip")
if [ -f "$BUILD_DIR/FredProxyKSP-Setup.exe" ]; then
  RELEASE_FILES+=("$BUILD_DIR/FredProxyKSP-Setup.exe")
fi

ls -lh "${RELEASE_FILES[@]}"

if [ -n "$TAG" ]; then
  echo ""
  echo "=== 5. Publishing to GitHub Release ($TAG) ==="
  if command -v gh >/dev/null 2>&1; then
    gh release create "$TAG" \
      "${RELEASE_FILES[@]}" \
      --title "$TAG - Keyless TLS Proxy Release" \
      --notes "Keyless TLS Proxy release $TAG" \
      --draft=false || \
    gh release upload "$TAG" \
      "${RELEASE_FILES[@]}" \
      --clobber
  else
    echo "Warning: 'gh' CLI not found. Skipping release upload."
  fi
fi

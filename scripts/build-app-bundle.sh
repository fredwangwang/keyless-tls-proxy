#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$ROOT_DIR/build"

APP_DIR="$ROOT_DIR/build/MacTokenApp.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
PLUGINS_DIR="$CONTENTS_DIR/PlugIns"
EXT_DIR="$PLUGINS_DIR/MacTokenExtension.appex"
EXT_CONTENTS_DIR="$EXT_DIR/Contents"
EXT_MACOS_DIR="$EXT_CONTENTS_DIR/MacOS"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$PLUGINS_DIR" "$EXT_MACOS_DIR" "$CONTENTS_DIR/Resources/certs" "$EXT_CONTENTS_DIR/Resources/certs"
cp -R "$ROOT_DIR/certs/"* "$CONTENTS_DIR/Resources/certs/"
cp -R "$ROOT_DIR/certs/"* "$EXT_CONTENTS_DIR/Resources/certs/"

echo "=== 1. Building Go C-Archive (libctkbridge.a) ==="
cd "$ROOT_DIR"
CGO_ENABLED=1 go build -buildmode=c-archive -o build/libctkbridge.a ./internal/ctkbridge

echo "=== 2. Compiling App Extension Binary ==="
clang -fobjc-arc \
    -I"$ROOT_DIR/build" \
    -I"$ROOT_DIR/mac-provider" \
    "$ROOT_DIR/mac-provider"/TokenDriver.m \
    "$ROOT_DIR/mac-provider"/Token.m \
    "$ROOT_DIR/mac-provider"/TokenSession.m \
    "$ROOT_DIR/mac-provider"/ExtensionMain.m \
    "$ROOT_DIR/build/libctkbridge.a" \
    -framework Foundation \
    -framework Security \
    -framework CryptoTokenKit \
    -lresolv \
    -lpthread \
    -o "$EXT_MACOS_DIR/MacTokenExtension"

echo "=== 3. Compiling Cocoa Container App Binary ==="
clang -fobjc-arc \
    -I"$ROOT_DIR/build" \
    -I"$ROOT_DIR/mac-provider" \
    "$ROOT_DIR/mac-provider"/AppMain.m \
    "$ROOT_DIR/build/libctkbridge.a" \
    -framework Cocoa \
    -framework Security \
    -framework CryptoTokenKit \
    -lresolv \
    -lpthread \
    -o "$MACOS_DIR/MacTokenApp"

echo "=== 4. Creating Info.plist Files ==="
cat << 'EOF' > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>MacTokenApp</string>
	<key>CFBundleExecutable</key>
	<string>MacTokenApp</string>
	<key>CFBundleIdentifier</key>
	<string>com.fredprx.mactoken.app</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>MacTokenApp</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
</dict>
</plist>
EOF

cat << 'EOF' > "$EXT_CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>MacToken Extension</string>
	<key>CFBundleExecutable</key>
	<string>MacTokenExtension</string>
	<key>CFBundleIdentifier</key>
	<string>com.fredprx.mactoken.app.extension</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>MacTokenExtension</string>
	<key>CFBundlePackageType</key>
	<string>XPC!</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>NSExtension</key>
	<dict>
		<key>NSExtensionAttributes</key>
		<dict>
			<key>com.apple.ctk.class-id</key>
			<string>com.fredprx.mactoken.app.extension</string>
			<key>com.apple.ctk.driver-class</key>
			<string>MacTokenDriver</string>
			<key>com.apple.ctk.token-type</key>
			<string>token</string>
		</dict>
		<key>NSExtensionPointIdentifier</key>
		<string>com.apple.ctk-tokens</string>
	</dict>
</dict>
</plist>
EOF

echo "=== 5. Code Signing App Bundle with Entitlements ==="
codesign -s - --force --entitlements "$ROOT_DIR/mac-provider/extension.entitlements" "$EXT_DIR"
codesign -s - --force --entitlements "$ROOT_DIR/mac-provider/app.entitlements" "$APP_DIR"


echo "=== Build Complete! App bundle created at build/MacTokenApp.app ==="


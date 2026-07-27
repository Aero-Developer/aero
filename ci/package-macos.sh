#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Package Aero for macOS on Apple Silicon (arm64) into a self-contained, ad-hoc-signed Aero.app zip.
#
# Runs on a Mac (locally or on a GitHub `macos-latest` Apple-Silicon runner). It:
#   1. builds the Rust core (libaero_core.dylib) and the Qt GUI (Aero.app),
#   2. bundles the Qt frameworks with macdeployqt,
#   3. drops the Tor Expert Bundle (tor + geoip files) into Aero.app/Contents/MacOS/tor,
#   4. ad-hoc code-signs the bundle (Apple Silicon refuses to run unsigned code),
#   5. zips it to dist/Aero-<version>-macOS-arm64.zip with a SHA-256 checksum.
#
# Usage:  ci/package-macos.sh <version>        (e.g. ci/package-macos.sh 0.1.23)
# Env:    TOR_BROWSER_VERSION  override the Tor Expert Bundle version (default below)
#         MACDEPLOYQT           path to macdeployqt if not on PATH
set -euo pipefail

VERSION="${1:?usage: package-macos.sh <version>}"
TOR_BROWSER_VERSION="${TOR_BROWSER_VERSION:-14.5.6}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$REPO_ROOT/core"
GUI_DIR="$REPO_ROOT/frontend/gui"
BUILD_DIR="$GUI_DIR/build"
DIST_DIR="$REPO_ROOT/dist"
APP="$BUILD_DIR/Aero.app"

echo "==> Building Rust core (release, host arch = $(uname -m))"
( cd "$CORE_DIR" && cargo build --release --locked )

echo "==> Configuring + building the Qt GUI (Aero.app)"
cmake -S "$GUI_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --config Release -j

[ -d "$APP" ] || { echo "ERROR: $APP was not produced"; exit 1; }

echo "==> Bundling Qt frameworks with macdeployqt"
MACDEPLOYQT_BIN="${MACDEPLOYQT:-$(command -v macdeployqt || true)}"
[ -n "$MACDEPLOYQT_BIN" ] || { echo "ERROR: macdeployqt not found (set \$MACDEPLOYQT)"; exit 1; }
"$MACDEPLOYQT_BIN" "$APP" -always-overwrite

echo "==> Fetching Tor Expert Bundle (macos-aarch64 $TOR_BROWSER_VERSION)"
TOR_TMP="$(mktemp -d)"
TOR_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_BROWSER_VERSION}/tor-expert-bundle-macos-aarch64-${TOR_BROWSER_VERSION}.tar.gz"
curl -fsSL "$TOR_URL" -o "$TOR_TMP/tor.tgz"
tar -xzf "$TOR_TMP/tor.tgz" -C "$TOR_TMP"

TOR_DEST="$APP/Contents/MacOS/tor"
mkdir -p "$TOR_DEST"
# The expert bundle layout is tor/tor + data/geoip{,6}; locate them defensively.
TOR_BIN="$(find "$TOR_TMP" -type f -name tor -perm -u+x | head -n1)"
[ -n "$TOR_BIN" ] || TOR_BIN="$(find "$TOR_TMP" -type f -name tor | head -n1)"
GEOIP="$(find "$TOR_TMP" -type f -name geoip | head -n1)"
GEOIP6="$(find "$TOR_TMP" -type f -name geoip6 | head -n1)"
[ -n "$TOR_BIN" ] && [ -n "$GEOIP" ] && [ -n "$GEOIP6" ] || { echo "ERROR: tor/geoip not found in bundle"; exit 1; }
cp "$TOR_BIN" "$TOR_DEST/tor"
cp "$GEOIP" "$TOR_DEST/geoip"
cp "$GEOIP6" "$TOR_DEST/geoip6"
chmod +x "$TOR_DEST/tor"
rm -rf "$TOR_TMP"

# Never ship user data: no wallets/config and no leftover Tor state.
rm -rf "$APP/Contents/MacOS/wallets" "$APP/Contents/MacOS/config" "$TOR_DEST/data" 2>/dev/null || true

echo "==> Ad-hoc code-signing the bundle (required to run on Apple Silicon)"
# Sign inner code first, then the app (deep). Ad-hoc identity "-": no cert, but satisfies the loader.
codesign --force --timestamp=none --sign - "$TOR_DEST/tor" || true
find "$APP/Contents" -type f \( -name "*.dylib" -o -name "*.framework" \) -exec \
    codesign --force --sign - {} \; 2>/dev/null || true
codesign --force --deep --sign - "$APP"

echo "==> Zipping"
mkdir -p "$DIST_DIR"
ZIP="$DIST_DIR/Aero-${VERSION}-macOS-arm64.zip"
rm -f "$ZIP"
# ditto preserves symlinks/permissions/bundle structure (plain zip mangles frameworks).
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"

SUM="$DIST_DIR/SHA256SUMS-${VERSION}-macos.txt"
shasum -a 256 "$ZIP" | sed "s#$DIST_DIR/##" > "$SUM"

echo "==> Done"
echo "    $ZIP"
cat "$SUM"
echo
echo "Note: this build is ad-hoc signed (not notarized). On first launch users must right-click the"
echo "app and choose Open (or run: xattr -dr com.apple.quarantine Aero.app) to bypass Gatekeeper."

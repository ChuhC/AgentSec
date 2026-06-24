#!/usr/bin/env bash
# agentSec macOS DMG packaging
# Usage: ./scripts/package-dmg.sh [--arch arm64|x64] [--skip-engine] [--skip-npm-install]
#
# Output: app/release/AgentSec-<version>-<arch>.dmg
# Note: PyInstaller engine must be built on macOS; use scripts/package-win.ps1 on Windows.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app"
ENGINE="$ROOT/engine"
ENGINE_BIN="$ENGINE/dist_pkg/agentsec-engine/agentsec-engine"

SKIP_ENGINE=0
SKIP_NPM_INSTALL=0
MAC_ARCH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-engine) SKIP_ENGINE=1 ;;
    --skip-npm-install) SKIP_NPM_INSTALL=1 ;;
    --arch=*) MAC_ARCH="${1#*=}" ;;
    --arch)
      shift
      MAC_ARCH="${1:?missing value for --arch}"
      ;;
    -h|--help)
      echo "Usage: $0 [--arch arm64|x64] [--skip-engine] [--skip-npm-install]"
      echo "  --arch              Target CPU (default: host native)"
      echo "  --skip-engine       Skip PyInstaller (engine unchanged)"
      echo "  --skip-npm-install  Skip npm install"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ -z "$MAC_ARCH" ]]; then
  case "$(uname -m)" in
    arm64) MAC_ARCH=arm64 ;;
    x86_64) MAC_ARCH=x64 ;;
    *) MAC_ARCH=arm64 ;;
  esac
fi

if [[ "$MAC_ARCH" != "arm64" && "$MAC_ARCH" != "x64" ]]; then
  echo "Invalid --arch: $MAC_ARCH (expected arm64 or x64)" >&2
  exit 1
fi

export AGENTSEC_MAC_ARCH="$MAC_ARCH"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: run macOS DMG packaging on Darwin; use scripts/package-win.ps1 on Windows" >&2
  exit 1
fi

export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"
export ELECTRON_BUILDER_BINARIES_MIRROR="${ELECTRON_BUILDER_BINARIES_MIRROR:-https://npmmirror.com/mirrors/electron-builder-binaries/}"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  unset ELECTRON_MIRROR ELECTRON_BUILDER_BINARIES_MIRROR
fi

echo "==> agentSec macOS DMG packaging ($MAC_ARCH)"
echo "    Root: $ROOT"

command -v node >/dev/null || { echo "Error: node not found" >&2; exit 1; }
command -v npm >/dev/null || { echo "Error: npm not found" >&2; exit 1; }

"$ROOT/scripts/setup-engine.sh" --with-pyinstaller --arch "$MAC_ARCH"

if [[ "$SKIP_NPM_INSTALL" -eq 0 ]]; then
  echo "==> npm install (app/)"
  (cd "$APP" && npm install)
else
  echo "==> Skipping npm install"
fi

if [[ ! -f "$APP/build/icon.icns" ]]; then
  echo "Warning: app/build/icon.icns not found; electron-builder will use the default icon" >&2
fi

cd "$APP"

if [[ "$SKIP_ENGINE" -eq 0 ]]; then
  echo "==> Freezing Python engine (PyInstaller, $MAC_ARCH)"
  npm run build:engine
else
  echo "==> Skipping engine freeze"
  if [[ ! -x "$ENGINE_BIN" ]]; then
    echo "Error: engine binary missing: $ENGINE_BIN" >&2
    echo "Run a full build first or omit --skip-engine" >&2
    exit 1
  fi
fi

echo "==> Building frontend + Electron main process"
npm run build

echo "==> electron-builder (dmg, $MAC_ARCH)"
npm run dist:mac -- --"$MAC_ARCH"

shopt -s nullglob
dmg_candidates=("$APP/release/"*-"$MAC_ARCH".dmg)
shopt -u nullglob

if [[ ${#dmg_candidates[@]} -eq 0 ]]; then
  echo "Error: no *-${MAC_ARCH}.dmg found under $APP/release" >&2
  ls -la "$APP/release/" 2>/dev/null || true
  exit 1
fi

DMG="$(ls -t "${dmg_candidates[@]}" | head -1)"
echo ""
echo "Done."
echo "  DMG: $DMG"
echo "  Size: $(du -h "$DMG" | cut -f1)"

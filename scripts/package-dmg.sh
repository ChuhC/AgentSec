#!/usr/bin/env bash
# agentSec macOS DMG 一键打包
# 用法：./scripts/package-dmg.sh [--skip-engine] [--skip-npm-install]
#
# 产物：app/release/agentSec-<version>.dmg
# 注意：PyInstaller 引擎须在 macOS 上构建；Windows 请用 scripts/package-win.ps1

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app"
ENGINE="$ROOT/engine"
VENV="$ENGINE/.venv"
ENGINE_BIN="$ENGINE/dist_pkg/agentsec-engine/agentsec-engine"

SKIP_ENGINE=0
SKIP_NPM_INSTALL=0

for arg in "$@"; do
  case "$arg" in
    --skip-engine) SKIP_ENGINE=1 ;;
    --skip-npm-install) SKIP_NPM_INSTALL=1 ;;
    -h|--help)
      echo "用法: $0 [--skip-engine] [--skip-npm-install]"
      echo "  --skip-engine       跳过 PyInstaller 引擎冻结（引擎未改时可加速）"
      echo "  --skip-npm-install  跳过 app/npm install"
      exit 0
      ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "错误: macOS DMG 打包请在 Darwin 上运行；Windows 请用 scripts/package-win.ps1" >&2
  exit 1
fi

export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"
export ELECTRON_BUILDER_BINARIES_MIRROR="${ELECTRON_BUILDER_BINARIES_MIRROR:-https://npmmirror.com/mirrors/electron-builder-binaries/}"

echo "==> agentSec macOS DMG 打包"
echo "    根目录: $ROOT"

command -v node >/dev/null || { echo "错误: 未找到 node" >&2; exit 1; }
command -v npm >/dev/null || { echo "错误: 未找到 npm" >&2; exit 1; }

"$ROOT/scripts/setup-engine.sh" --with-pyinstaller

if [[ "$SKIP_NPM_INSTALL" -eq 0 ]]; then
  echo "==> npm install (app/)"
  (cd "$APP" && npm install)
else
  echo "==> 跳过 npm install"
fi

if [[ ! -f "$APP/build/icon.icns" ]]; then
  echo "警告: 未找到 app/build/icon.icns，将使用 electron-builder 默认图标" >&2
fi

cd "$APP"

if [[ "$SKIP_ENGINE" -eq 0 ]]; then
  echo "==> 冻结 Python 引擎 (PyInstaller)"
  npm run build:engine
else
  echo "==> 跳过引擎冻结"
  if [[ ! -x "$ENGINE_BIN" ]]; then
    echo "错误: 引擎二进制不存在: $ENGINE_BIN" >&2
    echo "请先完整打包或去掉 --skip-engine" >&2
    exit 1
  fi
fi

echo "==> 构建前端 + Electron 主进程"
npm run build

echo "==> electron-builder (dmg)"
npm run dist:mac

DMG=$(ls -t "$APP/release/"*.dmg 2>/dev/null | head -1)
if [[ -n "$DMG" ]]; then
  echo ""
  echo "✓ 打包完成"
  echo "  DMG: $DMG"
  echo "  大小: $(du -h "$DMG" | cut -f1)"
else
  echo "错误: 未找到 dmg 产物" >&2
  exit 1
fi

#!/usr/bin/env bash
# agentSec macOS DMG 一键打包
# 用法：./scripts/package-dmg.sh [--skip-engine] [--skip-npm-install]
#
# 产物：app/release/agentSec-<version>.dmg

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app"
ENGINE="$ROOT/engine"
VENV="$ENGINE/.venv"

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

# 国内网络镜像（可通过环境变量覆盖）
export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"
export ELECTRON_BUILDER_BINARIES_MIRROR="${ELECTRON_BUILDER_BINARIES_MIRROR:-https://npmmirror.com/mirrors/electron-builder-binaries/}"

echo "==> agentSec DMG 打包"
echo "    根目录: $ROOT"

# ---- 前置检查 ----
command -v node >/dev/null || { echo "错误: 未找到 node" >&2; exit 1; }
command -v npm >/dev/null || { echo "错误: 未找到 npm" >&2; exit 1; }

if [[ ! -d "$VENV" ]]; then
  echo "==> 创建 Python 虚拟环境 ($VENV)"
  python3 -m venv "$VENV"
fi

echo "==> 安装/更新引擎依赖"
"$VENV/bin/pip" install -q -e "$ENGINE"
"$VENV/bin/pip" install -q pyinstaller

if [[ "$SKIP_NPM_INSTALL" -eq 0 ]]; then
  echo "==> npm install (app/)"
  (cd "$APP" && npm install)
else
  echo "==> 跳过 npm install"
fi

if [[ ! -f "$APP/build/icon.icns" ]]; then
  echo "警告: 未找到 app/build/icon.icns，将使用 electron-builder 默认图标" >&2
fi

# ---- 打包 ----
cd "$APP"

if [[ "$SKIP_ENGINE" -eq 0 ]]; then
  echo "==> 冻结 Python 引擎 (PyInstaller)"
  npm run build:engine
else
  echo "==> 跳过引擎冻结"
  if [[ ! -x "$ENGINE/dist_pkg/agentsec-engine/agentsec-engine" ]]; then
    echo "错误: 引擎二进制不存在，请先完整打包或去掉 --skip-engine" >&2
    exit 1
  fi
fi

echo "==> 构建前端 + Electron 主进程"
npm run build

echo "==> electron-builder (dmg)"
npx electron-builder --mac dmg

# ---- 输出产物 ----
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

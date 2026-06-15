#!/usr/bin/env bash
# 直接运行已打包的 .app（不装 dmg）
# 若不存在则先 build + electron-builder --mac dir
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app/release/mac/AgentSec.app"

if [[ ! -d "$APP" ]]; then
  echo "==> 未找到 $APP，先构建…"
  "$ROOT/scripts/package-dmg.sh" --skip-npm-install >/dev/null
  # dir 模式产物与 dmg 同目录；若只有 dmg 需先打一次包
  if [[ ! -d "$APP" ]]; then
    echo "==> 生成 .app (dir 模式)…"
    export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"
    export ELECTRON_BUILDER_BINARIES_MIRROR="${ELECTRON_BUILDER_BINARIES_MIRROR:-https://npmmirror.com/mirrors/electron-builder-binaries/}"
    (cd "$ROOT/app" && npm run build:engine && npm run build && npx electron-builder --mac dir)
  fi
fi

echo "==> 启动 $APP"
exec open -n "$APP"

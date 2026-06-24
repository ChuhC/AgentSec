#!/usr/bin/env bash
# 开发模式直接运行（热更新，走 engine/.venv，无需 dmg）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"

if [[ ! -x "$ROOT/engine/.venv/bin/python3" ]]; then
  "$ROOT/scripts/setup-engine.sh"
fi

cd "$ROOT/app"
[[ -d node_modules ]] || npm install
exec npm run dev

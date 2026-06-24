#!/usr/bin/env bash
# 配置 engine/.venv（Python 扫描引擎依赖）
# 用法：./scripts/setup-engine.sh [--with-pyinstaller]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$ROOT/engine"
VENV="$ENGINE/.venv"
WITH_PYINSTALLER=0

for arg in "$@"; do
  case "$arg" in
    --with-pyinstaller) WITH_PYINSTALLER=1 ;;
    -h|--help)
      echo "用法: $0 [--with-pyinstaller]"
      echo "  在 engine/.venv 安装 Python 扫描引擎（requires-python >= 3.10）"
      exit 0
      ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

python_ok() {
  local py="$1"
  "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null
}

find_python() {
  local cmd py
  for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" >/dev/null && python_ok "$(command -v "$cmd")"; then
      command -v "$cmd"
      return 0
    fi
  done
  if command -v uv >/dev/null; then
    py="$(uv python find 3.11 2>/dev/null || true)"
    if [[ -z "$py" ]]; then
      echo "==> 通过 uv 安装 Python 3.11 …" >&2
      uv python install 3.11 >/dev/null
      py="$(uv python find 3.11)"
    fi
    if [[ -n "$py" ]] && python_ok "$py"; then
      echo "$py"
      return 0
    fi
  fi
  return 1
}

venv_python_ok() {
  [[ -x "$VENV/bin/python3" ]] && python_ok "$VENV/bin/python3"
}

if venv_python_ok; then
  echo "==> 使用已有虚拟环境 ($VENV, $($VENV/bin/python3 --version 2>&1))"
else
  if [[ -d "$VENV" ]]; then
    echo "==> 移除不兼容的旧虚拟环境（macOS 自带 python3 为 3.8，不能复用已有 .venv）"
    rm -rf "$VENV"
  fi
  PY="$(find_python)" || {
    echo "错误: 需要 Python 3.10+。" >&2
    echo "  推荐: brew install python@3.11  或  uv python install 3.11" >&2
    exit 1
  }
  echo "==> 创建虚拟环境 ($VENV)，解释器: $PY ($("$PY" --version 2>&1))"
  "$PY" -m venv "$VENV"
fi

echo "==> 安装/更新引擎依赖"
"$VENV/bin/pip" install -q -U pip
"$VENV/bin/pip" install -e "$ENGINE"

if [[ "$WITH_PYINSTALLER" -eq 1 ]]; then
  "$VENV/bin/pip" install -q pyinstaller
fi

echo "==> 引擎已就绪: $VENV/bin/python3"

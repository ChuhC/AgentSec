#!/usr/bin/env bash
# Configure engine/.venv (Python scan engine dependencies)
# Usage: ./scripts/setup-engine.sh [--with-pyinstaller] [--arch arm64|x64]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$ROOT/engine"
VENV="$ENGINE/.venv"
WITH_PYINSTALLER=0
MAC_ARCH="${AGENTSEC_MAC_ARCH:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-pyinstaller) WITH_PYINSTALLER=1 ;;
    --arch=*) MAC_ARCH="${1#*=}" ;;
    --arch)
      shift
      MAC_ARCH="${1:?missing value for --arch}"
      ;;
    -h|--help)
      echo "Usage: $0 [--with-pyinstaller] [--arch arm64|x64]"
      echo "  Install the Python scan engine into engine/.venv (requires-python >= 3.10)"
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

python_ok() {
  local py="$1"
  "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null
}

venv_arch_ok() {
  [[ -x "$VENV/bin/python3" ]] || return 1
  python_ok "$VENV/bin/python3" || return 1
  local kind
  kind="$(file "$VENV/bin/python3" 2>/dev/null || true)"
  if [[ "$MAC_ARCH" == "x64" ]]; then
    [[ "$kind" == *x86_64* ]]
  else
    [[ "$kind" == *arm64* ]] || [[ "$kind" == *x86_64* && "$(uname -m)" == "x86_64" ]]
  fi
}

find_python_arm64() {
  local cmd py
  for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" >/dev/null && python_ok "$(command -v "$cmd")"; then
      command -v "$cmd"
      return 0
    fi
  done
  if command -v uv >/dev/null; then
    local target="cpython-3.11-macos-aarch64-none"
    py="$(uv python find "$target" 2>/dev/null || true)"
    if [[ -z "$py" ]]; then
      echo "==> Installing arm64 Python 3.11 via uv …" >&2
      uv python install "$target"
      py="$(uv python find "$target")"
    fi
    if [[ -n "$py" ]] && python_ok "$py"; then
      echo "$py"
      return 0
    fi
  fi
  return 1
}

find_python_x64() {
  if ! command -v uv >/dev/null; then
    for cmd in python3.11 python3.10 python3; do
      if command -v "$cmd" >/dev/null; then
        local resolved kind
        resolved="$(command -v "$cmd")"
        kind="$(file "$resolved" 2>/dev/null || true)"
        if [[ "$kind" == *x86_64* ]] && python_ok "$resolved"; then
          echo "$resolved"
          return 0
        fi
      fi
    done
    return 1
  fi
  local target="cpython-3.11-macos-x86_64-none"
  local py
  py="$(uv python find "$target" 2>/dev/null || true)"
  if [[ -z "$py" ]]; then
    echo "==> Installing x86_64 Python 3.11 via uv …" >&2
    uv python install "$target"
    py="$(uv python find "$target")"
  fi
  if [[ -n "$py" ]] && python_ok "$py"; then
    echo "$py"
    return 0
  fi
  return 1
}

find_python() {
  if [[ "$MAC_ARCH" == "x64" ]]; then
    find_python_x64
  else
    find_python_arm64
  fi
}

create_venv() {
  local py="$1"
  if [[ "$MAC_ARCH" == "x64" && "$(uname -m)" == "arm64" ]]; then
    arch -x86_64 "$py" -m venv "$VENV"
  else
    "$py" -m venv "$VENV"
  fi
}

run_pip() {
  if [[ "$MAC_ARCH" == "x64" && "$(uname -m)" == "arm64" ]]; then
    arch -x86_64 "$VENV/bin/pip" "$@"
  else
    "$VENV/bin/pip" "$@"
  fi
}

if venv_arch_ok; then
  echo "==> Using existing venv ($VENV, $MAC_ARCH, $($VENV/bin/python3 --version 2>&1))"
else
  if [[ -d "$VENV" ]]; then
    echo "==> Removing incompatible venv at $VENV"
    rm -rf "$VENV"
  fi
  PY="$(find_python)" || {
    echo "Error: Python 3.10+ required for $MAC_ARCH." >&2
    if [[ "$MAC_ARCH" == "x64" ]]; then
      echo "  Install uv, then retry: https://docs.astral.sh/uv/" >&2
    else
      echo "  Try: brew install python@3.11  or  uv python install 3.11" >&2
    fi
    exit 1
  }
  echo "==> Creating venv ($VENV, $MAC_ARCH) with $PY ($("$PY" --version 2>&1))"
  create_venv "$PY"
fi

echo "==> Installing/updating engine dependencies"
run_pip install -q -U pip
run_pip install -q -e "$ENGINE"

if [[ "$WITH_PYINSTALLER" -eq 1 ]]; then
  run_pip install -q pyinstaller
fi

echo "==> Engine ready ($MAC_ARCH): $VENV/bin/python3"

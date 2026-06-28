#!/usr/bin/env bash
# Run Python engine unit tests
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$ROOT/engine"

if [[ -x "$ENGINE/.venv/bin/python" ]]; then
  PY="$ENGINE/.venv/bin/python"
elif [[ -x "$ENGINE/.venv/bin/python3" ]]; then
  PY="$ENGINE/.venv/bin/python3"
else
  PY="${PYTHON:-python3}"
fi

echo "==> engine tests ($("$PY" --version 2>&1))"
"$PY" -m pip install -q -U pip
"$PY" -m pip install -q -e "$ENGINE[dev]"
cd "$ENGINE"
exec "$PY" -m pytest -q "$@"

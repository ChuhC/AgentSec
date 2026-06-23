"""统一配置文件：{data_dir}/config.json

优先级（逐项）：环境变量 > config.json > 内置默认值。
环境变量保留用于 CI / 临时覆盖，日常请编辑配置文件或在设置页修改。
"""

from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from typing import Any, Optional

from .paths import default_data_dir

CONFIG_VERSION = 1
CONFIG_FILENAME = "config.json"

_lock = threading.Lock()
_cache: Optional[dict] = None

DEFAULT_CONFIG: dict[str, Any] = {
    "version": CONFIG_VERSION,
    "ui": {
        "language": "zh",
        "theme": "glass",
        "confirm_update": True,
        "confirm_uninstall": True,
        "confirm_disable": True,
    },
    "scan": {
        "cve_online": True,
    },
    "agents": {
        "hermes_home": "",
        "openclaw_home": "",
        "hermes_bin": "",
        "openclaw_bin": "",
    },
    "dev": {
        "debug": False,
        "engine_dir": "",
        "python": "",
    },
}

# 环境变量 → (section, key)；data_dir 仅由 paths/default_data_dir 处理
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "AGENTSEC_HERMES_HOME": ("agents", "hermes_home"),
    "AGENTSEC_OPENCLAW_HOME": ("agents", "openclaw_home"),
    "AGENTSEC_HERMES_BIN": ("agents", "hermes_bin"),
    "AGENTSEC_OPENCLAW_BIN": ("agents", "openclaw_bin"),
}


def config_path(data_dir: Optional[str] = None) -> str:
    return os.path.join(data_dir or default_data_dir(), CONFIG_FILENAME)


def _deep_merge(base: dict, patch: dict) -> dict:
    out = deepcopy(base)
    for key, val in patch.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def _apply_env_overrides(cfg: dict) -> dict:
    out = deepcopy(cfg)
    if os.environ.get("AGENTSEC_CVE_OFFLINE"):
        out.setdefault("scan", {})["cve_online"] = False
    if os.environ.get("AGENTSEC_DEBUG") == "1":
        out.setdefault("dev", {})["debug"] = True
    if os.environ.get("AGENTSEC_ENGINE_DIR"):
        out.setdefault("dev", {})["engine_dir"] = os.environ["AGENTSEC_ENGINE_DIR"]
    if os.environ.get("AGENTSEC_PYTHON"):
        out.setdefault("dev", {})["python"] = os.environ["AGENTSEC_PYTHON"]
    for env_key, (section, field) in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val:
            out.setdefault(section, {})[field] = val
    return out


def _load_raw(data_dir: Optional[str] = None) -> dict:
    path = config_path(data_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.isfile(path):
        return deepcopy(DEFAULT_CONFIG)
    try:
        with open(path, encoding="utf-8") as f:
            parsed = json.load(f)
        if not isinstance(parsed, dict):
            return deepcopy(DEFAULT_CONFIG)
        merged = _deep_merge(DEFAULT_CONFIG, parsed)
        merged["version"] = CONFIG_VERSION
        return merged
    except (OSError, json.JSONDecodeError):
        return deepcopy(DEFAULT_CONFIG)


def get_config(*, reload: bool = False, data_dir: Optional[str] = None) -> dict:
    global _cache
    with _lock:
        if reload or _cache is None:
            _cache = _apply_env_overrides(_load_raw(data_dir))
        return deepcopy(_cache)


def patch_config(patch: dict, *, data_dir: Optional[str] = None) -> dict:
    global _cache
    with _lock:
        current = _load_raw(data_dir)
        merged = _deep_merge(current, patch)
        merged["version"] = CONFIG_VERSION
        path = config_path(data_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
            f.write("\n")
        _cache = _apply_env_overrides(merged)
        return deepcopy(_cache)


def _non_empty(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def get_agent_home(kind: str) -> Optional[str]:
    cfg = get_config()
    key = f"{kind.lower()}_home"
    return _non_empty(cfg.get("agents", {}).get(key))


def get_agent_bin(kind: str) -> Optional[str]:
    cfg = get_config()
    key = f"{kind.lower()}_bin"
    return _non_empty(cfg.get("agents", {}).get(key))


def cve_online(default: bool = True) -> bool:
    cfg = get_config()
    val = cfg.get("scan", {}).get("cve_online", default)
    return bool(val)


def dev_debug() -> bool:
    return bool(get_config().get("dev", {}).get("debug"))


def dev_engine_dir() -> Optional[str]:
    return _non_empty(get_config().get("dev", {}).get("engine_dir"))


def dev_python() -> Optional[str]:
    return _non_empty(get_config().get("dev", {}).get("python"))

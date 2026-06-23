"""跨平台路径：数据目录、用户 home、Finding 命中路径解析。"""

from __future__ import annotations

import os
import re
import sys

# 与 Electron productName 一致，便于打包态通过 AGENTSEC_DATA_DIR 对齐 userData
APP_DATA_DIR_NAME = "AgentSec"

_LINE_SUFFIX_RE = re.compile(r":\d+$")


def user_home() -> str:
    return os.path.expanduser("~")


def default_data_dir() -> str:
    """应用数据目录（快照、日志等）。

    优先级：AGENTSEC_DATA_DIR 环境变量 > 各平台默认位置。
    macOS : ~/Library/Application Support/AgentSec/
    Windows : %APPDATA%/AgentSec/
    Linux   : $XDG_DATA_HOME/AgentSec/ 或 ~/.local/share/AgentSec/
    """
    override = os.environ.get("AGENTSEC_DATA_DIR")
    if override:
        return override

    home = user_home()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or home
        return os.path.join(base, APP_DATA_DIR_NAME)
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", APP_DATA_DIR_NAME)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return os.path.join(xdg, APP_DATA_DIR_NAME)
    return os.path.join(home, ".local", "share", APP_DATA_DIR_NAME)


def venv_python(venv_root: str) -> str:
    """engine/.venv 内 Python 解释器路径。"""
    if sys.platform == "win32":
        return os.path.join(venv_root, "Scripts", "python.exe")
    return os.path.join(venv_root, "bin", "python")


def frozen_engine_filename() -> str:
    """PyInstaller 冻结引擎可执行文件名。"""
    return "agentsec-engine.exe" if sys.platform == "win32" else "agentsec-engine"


def frozen_engine_dist_dir(engine_root: str) -> str:
    """PyInstaller --onedir 输出目录（含可执行文件与依赖）。"""
    return os.path.join(engine_root, "dist_pkg", "agentsec-engine")


def frozen_engine_binary(engine_root: str) -> str:
    return os.path.join(frozen_engine_dist_dir(engine_root), frozen_engine_filename())


def finding_path_only(location: str) -> str:
    """`/path/SKILL.md:42` → `/path/SKILL.md`。"""
    if not location:
        return ""
    raw = str(location).strip()
    if raw.startswith("/") or raw.startswith("~") or (len(raw) >= 2 and raw[1] == ":"):
        raw = _LINE_SUFFIX_RE.sub("", raw)
    return raw


def normalize_readable_path(location: str) -> str:
    """展开 ~ 并 realpath，供 file.read 鉴权与打开。"""
    raw = finding_path_only(location)
    if not raw:
        return ""
    return os.path.realpath(os.path.expanduser(raw))


def safe_normalize_readable_path(location: str) -> str:
    """同 normalize_readable_path，realpath 失败时不抛错。"""
    raw = finding_path_only(location)
    if not raw:
        return ""
    expanded = os.path.expanduser(raw)
    try:
        return os.path.realpath(expanded)
    except OSError:
        return expanded

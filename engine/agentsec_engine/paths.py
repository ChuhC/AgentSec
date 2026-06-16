"""Finding 命中路径解析（macOS 静态扫描）。"""

from __future__ import annotations

import os
import re

_LINE_SUFFIX_RE = re.compile(r":\d+$")


def finding_path_only(location: str) -> str:
    """`/path/SKILL.md:42` → `/path/SKILL.md`。"""
    if not location:
        return ""
    raw = str(location).strip()
    if raw.startswith("/") or raw.startswith("~"):
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

"""威胁检测默认加白路径。

red-teaming 技能目录故意包含攻击性样例，默认不参与 ATR 威胁统计。
"""

from __future__ import annotations

import os
from typing import List

from .paths import finding_path_only, normalize_readable_path

# 相对用户 home：~/.hermes/skills/red-teaming
_WHITELIST_REL = os.path.join(".hermes", "skills", "red-teaming")


def default_whitelist_roots() -> List[str]:
    home = os.path.expanduser("~")
    root = os.path.realpath(os.path.join(home, _WHITELIST_REL))
    return [root]


def _path_only(location: str) -> str:
    return finding_path_only(location)


def is_whitelisted_path(path: str) -> bool:
    """路径是否位于默认加白目录下。"""
    raw = _path_only(path)
    if not raw:
        return False
    try:
        norm = normalize_readable_path(raw)
    except OSError:
        norm = os.path.expanduser(raw)
    for root in default_whitelist_roots():
        if norm == root or norm.startswith(root + os.sep):
            return True
    return False


def finding_locations(finding: dict) -> List[str]:
    locs = list(finding.get("locations") or [])
    loc = finding.get("location")
    if loc:
        locs.append(loc)
    return locs


def is_finding_fully_whitelisted(finding: dict) -> bool:
    """finding 的全部命中位置均在加白目录内。"""
    locs = finding_locations(finding)
    if not locs:
        return False
    return all(is_whitelisted_path(loc) for loc in locs)


def apply_default_whitelist_to_snapshot(snap: dict) -> dict:
    """将完全位于加白目录内的威胁写入 ignored_threat_keys（与用户手动忽略一致）。"""
    keys = list(snap.get("ignored_threat_keys") or [])
    seen = set(keys)
    for f in snap.get("exposure_findings", []):
        if not is_finding_fully_whitelisted(f):
            continue
        key = f"{f.get('source')}::{f.get('id')}"
        if key not in seen:
            seen.add(key)
            keys.append(key)
    snap["ignored_threat_keys"] = keys
    return snap

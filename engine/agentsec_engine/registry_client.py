"""包 registry 查询（PyPI / npm），供版本 enrichment 使用。"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, Optional

_TIMEOUT = 6
_cache: Dict[str, Optional[str]] = {}


def fetch_pypi_latest(package: str) -> Optional[str]:
    key = f"pypi:{package}"
    if key in _cache:
        return _cache[key]
    ver: Optional[str] = None
    try:
        url = f"https://pypi.org/pypi/{package}/json"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
            ver = (data.get("info") or {}).get("version")
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError):
        ver = None
    _cache[key] = ver
    return ver


def fetch_npm_latest(package: str) -> Optional[str]:
    key = f"npm:{package}"
    if key in _cache:
        return _cache[key]
    ver: Optional[str] = None
    try:
        # scoped packages need URL encoding
        slug = package.replace("/", "%2f")
        url = f"https://registry.npmjs.org/{slug}/latest"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
            ver = data.get("version")
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError):
        ver = None
    _cache[key] = ver
    return ver

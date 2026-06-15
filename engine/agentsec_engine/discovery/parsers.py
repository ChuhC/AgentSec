"""真实配置解析助手：把真机 Agent 安装解析为 Agent / Asset。

真机产品格式（已调研）：
  Hermes   : ~/.hermes/config.yaml（YAML，mcp_servers/model/...）
             ~/.hermes/.update_check（version）
             ~/.hermes/skills/**/SKILL.md（YAML frontmatter）
             ~/.hermes/hermes-agent/package.json（npm 依赖）
  OpenClaw : ~/.openclaw/openclaw.json 或 settings.json（不含 claw3d/，其为 Hermes 桌面 UI）

凭证不入对象：env/token 仅记键名引用，绝不存值（NF-S2，配合 Reporter Redactor）。
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from ..models import (
    Agent,
    Asset,
    AssetStatus,
    AssetType,
    FindingSource,
    PermissionEntry,
    Severity,
)

S = Severity
ST = AssetStatus
AT = AssetType
SRC = FindingSource

# 权限关键字 → (中文名, 类别, 严重度)
_PERM_MAP = {
    "exec": ("执行命令、管理进程", "Shell", S.HIGH),
    "shell": ("执行 Shell 命令", "Shell", S.HIGH),
    "write": ("写入、创建、删除文件", "文件", S.HIGH),
    "delete": ("删除文件", "文件", S.HIGH),
    "read": ("读取文件", "文件", S.MEDIUM),
    "file": ("读取本地文件", "文件", S.MEDIUM),
    "network": ("访问网络", "网络", S.MEDIUM),
    "net": ("访问网络", "网络", S.MEDIUM),
    "db": ("读写数据库", "工具", S.MEDIUM),
    "knowledge": ("读取知识库内容", "知识库", S.LOW),
}


def perm(pid: str, key: str, source: FindingSource, label: str,
         severity: Optional[Severity] = None) -> PermissionEntry:
    name, category, sev = _PERM_MAP.get(key, (key, "工具", S.LOW))
    return PermissionEntry(
        id=pid, name=name, category=category,
        source=source.value, source_label=label,
        severity=(severity or sev).value,
    )


def read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_yaml(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return None


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def parse_skill_frontmatter(path: str) -> Dict:
    """读取 SKILL.md 的 YAML frontmatter（无则返回空 dict）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read(8192)
    except OSError:
        return {}
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    try:
        data = yaml.safe_load(m.group(1))
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError:
        return {}


_VER_RE = re.compile(r"[0-9][\w.\-]*")


def clean_version(spec: str) -> str:
    m = _VER_RE.search(spec or "")
    return m.group(0) if m else (spec or "")


def deps_from_package_json(path: str, agent_id: str) -> List[Asset]:
    pkg = read_json(path)
    if not pkg:
        return []
    out = []
    for name, spec in (pkg.get("dependencies") or {}).items():
        out.append(dep_asset(agent_id, name, clean_version(str(spec)), "npm"))
    return out


def deps_from_requirements(path: str, agent_id: str) -> List[Asset]:
    if not os.path.isfile(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)?\s*([\w.\-]+)?", line)
        if m:
            out.append(dep_asset(agent_id, m.group(1), m.group(2) or "", "PyPI"))
    return out


def dep_asset(agent_id: str, name: str, version: str, ecosystem: str) -> Asset:
    return Asset(
        id=f"{agent_id}-dep-{name}", agent_id=agent_id, type=AT.DEPENDENCY.value,
        name=name, version=version, status=ST.ENABLED.value,
        purpose=f"{ecosystem} 依赖组件", source=agent_id.capitalize(), ecosystem=ecosystem,
        can_disable=False, can_uninstall=False,
    )

"""真实配置解析助手：把真机 Agent 安装解析为 Agent / Asset。

真机产品格式（已调研）：
  Hermes   : ~/.hermes/config.yaml（YAML，mcp_servers/model/...）
             ~/.hermes/.update_check（version）
             ~/.hermes/skills/**/SKILL.md（YAML frontmatter）
             ~/.hermes/hermes-agent（npm workspace + package-lock + pyproject.toml）
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


def perms_from_mcp_server(name: str, srv: dict) -> List[PermissionEntry]:
    """从 MCP 服务配置推断权限（命令行启发式 + 网络访问）。"""
    out: List[PermissionEntry] = []
    seen: set[str] = set()
    label = f"{name} MCP"

    def add(key: str, severity: Optional[Severity] = None) -> None:
        k = key.lower()
        if k in seen:
            return
        seen.add(k)
        out.append(perm(f"hermes-{name}-{k}", k, SRC.MCP, label, severity))

    add("network")
    cmd = " ".join([str(srv.get("command", ""))] + [str(a) for a in srv.get("args", [])]).lower()
    if any(t in cmd for t in ("filesystem", "file", "fs", "read", "write", "directory")):
        add("read")
        if any(t in cmd for t in ("write", "filesystem", "delete")):
            add("write")
    if any(t in cmd for t in ("shell", "bash", "terminal", "exec", "sh ")):
        add("exec", S.HIGH)
    if any(t in cmd for t in ("postgres", "sqlite", "mysql", "database", "db")):
        add("db")
    return out


def _norm_perm_keys(raw) -> List[str]:
    if isinstance(raw, str):
        return [raw.lower()]
    if isinstance(raw, list):
        keys: List[str] = []
        for item in raw:
            keys.extend(_norm_perm_keys(item))
        return keys
    if isinstance(raw, dict):
        keys = []
        for k, v in raw.items():
            if v in (True, "true", "yes", 1, "required"):
                keys.append(str(k).lower())
            elif v not in (False, "false", "no", 0, None, ""):
                keys.extend(_norm_perm_keys(v))
        return keys
    return []


def perms_from_skill_frontmatter(rel_id: str, label: str, fm: dict) -> List[PermissionEntry]:
    """从 SKILL.md frontmatter 解析 prerequisites / granted_permissions 等。"""
    out: List[PermissionEntry] = []
    seen: set[str] = set()

    def add(key: str, severity: Optional[Severity] = None) -> None:
        k = key.lower()
        if k in seen:
            return
        seen.add(k)
        out.append(perm(f"hermes-sk-{rel_id}-{k}", k, SRC.SKILL, label, severity))

    pre = fm.get("prerequisites") if isinstance(fm.get("prerequisites"), dict) else {}
    if pre.get("commands") or pre.get("bins") or pre.get("any_bins"):
        add("exec", S.MEDIUM)
    if pre.get("env") or pre.get("environment"):
        add("network", S.LOW)

    for key in _norm_perm_keys(fm.get("granted_permissions")):
        add(key)
    for key in _norm_perm_keys(fm.get("permissions")):
        add(key)

    return out


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
    slug = _dep_slug(name, version)
    return Asset(
        id=f"{agent_id}-dep-{slug}", agent_id=agent_id, type=AT.DEPENDENCY.value,
        name=name, version=version, status=ST.ENABLED.value,
        purpose=f"{ecosystem} 依赖组件", source=agent_id.capitalize(), ecosystem=ecosystem,
        can_disable=False, can_uninstall=False,
    )


def _dep_slug(name: str, version: str) -> str:
    raw = f"{name}@{version or 'unknown'}"
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", raw).strip("-")[:120]


def _lock_package_name(path: str) -> Optional[str]:
    """从 lock v2/v3 的 packages 键提取 npm 包名。"""
    if not path:
        return None
    return path.split("node_modules/")[-1] or None


def _parse_lock_packages(lock_path: str) -> List[Tuple[str, str]]:
    """package-lock.json → [(name, resolved_version), ...]。"""
    lock = read_json(lock_path)
    if not lock:
        return []
    out: List[Tuple[str, str]] = []
    seen = set()
    for path, info in (lock.get("packages") or {}).items():
        if not path or not isinstance(info, dict):
            continue
        name = _lock_package_name(path)
        ver = info.get("version")
        if not name or not ver:
            continue
        key = (name, ver)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _iter_workspace_package_json(root: str) -> List[str]:
    """workspace 内全部 package.json（跳过 node_modules）。"""
    paths: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "dist", "build")]
        if "package.json" in filenames:
            paths.append(os.path.join(dirpath, "package.json"))
    return paths


def _parse_pyproject_deps(path: str) -> List[Tuple[str, str]]:
    if not os.path.isfile(path):
        return []
    try:
        import tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:  # noqa: BLE001
        return []
    raw_deps = list((data.get("project") or {}).get("dependencies") or [])
    out: List[Tuple[str, str]] = []
    for raw in raw_deps:
        spec = str(raw).strip()
        if not spec:
            continue
        name = re.split(r"[<>=!~\[]", spec, maxsplit=1)[0].strip()
        ver = clean_version(spec)
        if name:
            out.append((name, ver))
    return out


def deps_from_pyproject(path: str, agent_id: str) -> List[Asset]:
    out: List[Asset] = []
    for name, ver in _parse_pyproject_deps(path):
        if name:
            out.append(dep_asset(agent_id, name, ver, "PyPI"))
    return out


def deps_from_npm_workspace(agent_dir: str, agent_id: str) -> List[Asset]:
    """npm workspace 全量依赖：lock 已安装树 + 各 workspace manifest + pyproject。"""
    if not os.path.isdir(agent_dir):
        return []

    by_key: Dict[Tuple[str, str, str], Asset] = {}
    lock_path = os.path.join(agent_dir, "package-lock.json")
    lock_best: Dict[str, str] = {}
    for name, ver in _parse_lock_packages(lock_path):
        lock_best[name] = ver
        key = (name, ver, "npm")
        if key not in by_key:
            by_key[key] = dep_asset(agent_id, name, ver, "npm")

    for pkg_path in _iter_workspace_package_json(agent_dir):
        pkg = read_json(pkg_path) or {}
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            for name, spec in (pkg.get(section) or {}).items():
                ver = lock_best.get(str(name)) or clean_version(str(spec))
                if not ver:
                    continue
                key = (str(name), ver, "npm")
                if key not in by_key:
                    by_key[key] = dep_asset(agent_id, str(name), ver, "npm")

    for name, ver in _parse_pyproject_deps(os.path.join(agent_dir, "pyproject.toml")):
        if not ver:
            continue
        key = (name, ver, "PyPI")
        if key not in by_key:
            by_key[key] = dep_asset(agent_id, name, ver, "PyPI")

    return sorted(by_key.values(), key=lambda a: (a.ecosystem or "", a.name.lower()))


def collect_listen_ports(cfg: dict, home: Optional[str] = None) -> List[str]:
    """从 config 与 gateway 运行态收集监听端口。"""
    ports: List[str] = []
    seen: set[str] = set()

    def add(port) -> None:
        if port is None:
            return
        s = str(port).strip()
        if s.isdigit() and s not in seen:
            seen.add(s)
            ports.append(s)

    web = cfg.get("web") or {}
    add(web.get("port"))

    for plat in (cfg.get("platforms") or {}).values():
        if not isinstance(plat, dict):
            continue
        extra = plat.get("extra") or {}
        add(extra.get("port"))

    gw = cfg.get("gateway") or {}
    add(gw.get("port"))

    if home:
        state_path = os.path.join(home, "gateway_state.json")
        state = read_json(state_path) or {}
        pid = state.get("pid")
        if pid:
            try:
                import subprocess

                out = subprocess.run(
                    ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout
                for line in out.splitlines():
                    m = re.search(r":(\d+)\s+\(LISTEN\)", line)
                    if m:
                        add(m.group(1))
            except (OSError, subprocess.TimeoutExpired):
                pass

    return sorted(ports, key=lambda x: int(x))


def parse_mcp_npm_package(srv: dict) -> Optional[str]:
    """从 MCP 配置解析 npm 包名（npx / node_modules 路径）。"""
    cmd = str(srv.get("command", "")).strip().lower()
    args = [str(a) for a in srv.get("args") or []]
    if cmd in ("npx", "npm"):
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a in ("-y", "--yes"):
                continue
            if a in ("--package",):
                skip_next = True
                continue
            if a.startswith("-"):
                continue
            # pkg@version → 取包名部分
            if "@" in a and not a.startswith("@"):
                return a.split("@", 1)[0]
            return a
    env = srv.get("env") or {}
    node_path = str(env.get("NODE_PATH", ""))
    if node_path and os.path.isdir(node_path):
        data = read_json(os.path.join(node_path, "package.json"))
        if data and data.get("name"):
            return str(data["name"])
    return None


def mcp_local_version(script_path: str) -> Optional[str]:
    """本地 MCP 脚本旁 package.json 版本。"""
    if not script_path:
        return None
    pkg_json = os.path.join(os.path.dirname(script_path), "package.json")
    data = read_json(pkg_json)
    if data and data.get("version"):
        return str(data["version"])
    return None


def installed_npm_version(package: str, search_root: str) -> Optional[str]:
    """在 node_modules 树中查找已安装版本。"""
    if not package or not search_root:
        return None
    parts = package.split("/")
    pkg_json = os.path.join(search_root, "node_modules", *parts, "package.json")
    data = read_json(pkg_json)
    if data and data.get("version"):
        return str(data["version"])
    return None


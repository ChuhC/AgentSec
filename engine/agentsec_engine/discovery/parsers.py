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
import shutil
import subprocess
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


def _skill_name_slug(name: str) -> str:
    return re.sub(r"[^\w-]", "-", str(name).lower()).strip("-")[:80] or "skill"


def discover_skills_in_roots(
    agent_id: str,
    source: str,
    roots: List[Tuple[str, str]],
) -> List[Asset]:
    """在多个 skill 根目录中发现 SKILL.md（按 roots 顺序，同名技能高优先级覆盖）。"""
    by_name: Dict[str, Asset] = {}

    for root, root_label in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root, followlinks=True):
            disabled = "SKILL.md.disabled" in files
            if "SKILL.md" not in files and not disabled:
                continue
            fname = "SKILL.md.disabled" if disabled else "SKILL.md"
            md = os.path.join(dirpath, fname)
            fm = parse_skill_frontmatter(md)
            name = str(fm.get("name") or os.path.basename(dirpath))
            if name in by_name:
                continue
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_id = rel.replace("/", "-")
            perms = perms_from_skill_frontmatter(rel_id, name, fm)
            desc = str(fm.get("description", "")) or "本机技能"
            if root_label:
                desc = f"{desc}（来源：{root_label}）"
            by_name[name] = Asset(
                id=f"{agent_id}-skill-{_skill_name_slug(name)}",
                agent_id=agent_id,
                type=AT.SKILL.value,
                name=name,
                version=str(fm.get("version", "")) or None,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=desc,
                source=source,
                permissions=perms,
                path=md,
                can_disable=True,
                can_uninstall=False,
            )

    return sorted(by_name.values(), key=lambda a: a.name.lower())


def openclaw_workspace_dir(home: str, cfg: dict) -> Optional[str]:
    """解析 OpenClaw 活动 workspace 路径。"""
    agents = cfg.get("agents") or {}
    defaults = agents.get("defaults") or {}
    ws = defaults.get("workspace")
    if ws:
        path = os.path.expanduser(str(ws))
        if os.path.isdir(path):
            return path
    fallback = os.path.join(home, "workspace")
    return fallback if os.path.isdir(fallback) else None


def resolve_openclaw_cli() -> Optional[str]:
    """定位 openclaw CLI（GUI 子进程 PATH 常不含 npm global bin）。"""
    from ..config import get_agent_bin

    configured = get_agent_bin("openclaw")
    if configured and os.path.isfile(configured) and os.access(configured, os.X_OK):
        return configured
    found = shutil.which("openclaw")
    if found:
        return found
    home = os.path.expanduser("~")
    for cand in (
        os.path.join(home, ".npm-global", "bin", "openclaw"),
        os.path.join(home, ".local", "bin", "openclaw"),
        "/opt/homebrew/bin/openclaw",
        "/usr/local/bin/openclaw",
    ):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def resolve_openclaw_bundled_skills_dir() -> Optional[str]:
    """定位 openclaw npm 包自带的 bundled skills/ 目录。"""
    candidates: List[str] = []
    cli = resolve_openclaw_cli()
    if cli:
        real = os.path.realpath(cli)
        base = os.path.basename(real).lower()
        if base.startswith("openclaw"):
            candidates.append(os.path.join(os.path.dirname(real), "skills"))
        prefix = os.path.dirname(os.path.dirname(real))
        candidates.append(os.path.join(prefix, "lib", "node_modules", "openclaw", "skills"))
        candidates.append(
            os.path.join(os.path.dirname(real), "..", "node_modules", "openclaw", "skills")
        )
    home = os.path.expanduser("~")
    candidates.extend(
        [
            os.path.join(home, ".npm-global", "lib", "node_modules", "openclaw", "skills"),
            os.path.join(home, ".local", "lib", "node_modules", "openclaw", "skills"),
        ]
    )
    seen: set[str] = set()
    for cand in candidates:
        try:
            path = os.path.realpath(cand)
        except OSError:
            continue
        if path in seen:
            continue
        seen.add(path)
        if os.path.isdir(path):
            return path
    return None


def resolve_openclaw_package_dir() -> Optional[str]:
    """定位 openclaw npm 包根目录（含 package.json / node_modules）。"""
    skills = resolve_openclaw_bundled_skills_dir()
    if skills:
        return os.path.dirname(skills)
    home = os.path.expanduser("~")
    for cand in (
        os.path.join(home, ".npm-global", "lib", "node_modules", "openclaw"),
        os.path.join(home, ".local", "lib", "node_modules", "openclaw"),
    ):
        if os.path.isdir(cand):
            return os.path.realpath(cand)
    return None


def _format_agent_version(ver: Optional[str]) -> str:
    if not ver:
        return ""
    s = str(ver).strip().lstrip("vV")
    m = re.search(r"[0-9][\w.\-]*", s)
    return f"v{m.group(0)}" if m else ""


def resolve_openclaw_installed_version(config_version: Optional[str] = None) -> str:
    """OpenClaw 已安装版本：config → npm package.json → CLI --version。"""
    if config_version:
        formatted = _format_agent_version(str(config_version))
        if formatted:
            return formatted
    pkg_root = resolve_openclaw_package_dir()
    if pkg_root:
        pkg = read_json(os.path.join(pkg_root, "package.json")) or {}
        formatted = _format_agent_version(pkg.get("version"))
        if formatted:
            return formatted
    cli = resolve_openclaw_cli()
    if cli:
        try:
            proc = subprocess.run(
                [cli, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            proc = None
        if proc and proc.returncode == 0:
            text = (proc.stdout or proc.stderr or "").strip()
            match = re.search(r"OpenClaw\s+([\d.]+(?:[.\-]\w+)*)", text, re.I)
            if match:
                return _format_agent_version(match.group(1))
    return ""


def openclaw_plugin_npm_roots(home: str) -> List[str]:
    """~/.openclaw/npm/projects/* 下各插件 npm 沙箱。"""
    roots: List[str] = []
    projects = os.path.join(home, "npm", "projects")
    if not os.path.isdir(projects):
        return roots
    for name in sorted(os.listdir(projects)):
        root = os.path.join(projects, name)
        if os.path.isfile(os.path.join(root, "package.json")):
            roots.append(os.path.realpath(root))
    return roots


def discover_openclaw_dependencies(home: str, agent_id: str = "openclaw") -> List[Asset]:
    """OpenClaw npm 主包 + 插件沙箱 + 可选 PyPI 清单。"""
    by_key: Dict[Tuple[str, str, str], Asset] = {}

    def ingest(deps: List[Asset], install_root: Optional[str], label: str) -> None:
        for d in deps:
            key = (d.name, d.version or "", d.ecosystem or "")
            if key in by_key:
                continue
            if label == "plugin":
                d.purpose = "插件 npm 依赖组件"
            elif label == "openclaw":
                d.purpose = "npm 依赖组件"
            if d.ecosystem == "npm" and install_root:
                d.manager = "npm"
                d.install_path = install_root
                d.package_name = d.name
                d.can_update = True
                d.can_uninstall = True
            elif d.ecosystem == "PyPI" and install_root:
                d.manager = "pip"
                d.install_path = install_root
                d.package_name = d.name
                d.can_update = True
                d.can_uninstall = True
            d.can_disable = False
            by_key[key] = d

    pkg_root = resolve_openclaw_package_dir()
    if pkg_root:
        ingest(deps_from_npm_workspace(pkg_root, agent_id), pkg_root, "openclaw")

    for plugin_root in openclaw_plugin_npm_roots(home):
        ingest(deps_from_npm_workspace(plugin_root, agent_id), plugin_root, "plugin")

    req_path = os.path.join(home, "requirements.txt")
    ingest(deps_from_requirements(req_path, agent_id), home, "local")

    py_path = os.path.join(home, "pyproject.toml")
    if os.path.isfile(py_path):
        ingest(deps_from_pyproject(py_path, agent_id), home, "local")

    return sorted(by_key.values(), key=lambda a: (a.ecosystem or "", a.name.lower()))


def openclaw_skill_roots(home: str, cfg: dict) -> List[Tuple[str, str]]:
    """OpenClaw skill 发现根目录（顺序与官方 precedence 一致，高→低）。"""
    roots: List[Tuple[str, str]] = []
    seen: set[str] = set()

    def add(path: Optional[str], label: str) -> None:
        if not path:
            return
        real = os.path.realpath(os.path.expanduser(path))
        if real in seen or not os.path.isdir(real):
            return
        seen.add(real)
        roots.append((real, label))

    ws = openclaw_workspace_dir(home, cfg)
    if ws:
        add(os.path.join(ws, "skills"), "workspace")
        add(os.path.join(ws, ".agents", "skills"), "project-agent")

    add(os.path.join(os.path.expanduser("~"), ".agents", "skills"), "personal-agent")
    add(os.path.join(home, "skills"), "managed")

    skills_cfg = cfg.get("skills") or {}
    load_cfg = skills_cfg.get("load") or {}
    for extra in load_cfg.get("extraDirs") or []:
        add(str(extra), "extra")

    add(resolve_openclaw_bundled_skills_dir(), "bundled")
    add(os.path.join(home, "plugin-skills"), "plugin")

    return roots


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


def _looks_secret_env_key(key: str) -> bool:
    k = key.lower()
    return any(t in k for t in ("key", "token", "secret", "password", "api"))


def describe_mcp_purpose(server_name: str, srv: dict) -> str:
    """生成可读的 MCP 用途描述（结构化 token，供 UI 本地化）。

    格式：__mcp__|label:<name>|npm:<pkg>|script:<basename>|creds:<k1,k2>
    避免把完整命令行路径塞进 purpose。
    """
    parts = [f"label:{server_name.strip() or 'mcp'}"]
    npm_pkg = parse_mcp_npm_package(srv)
    if npm_pkg:
        parts.append(f"npm:{npm_pkg}")
    else:
        for arg in srv.get("args") or []:
            a = str(arg)
            if a.endswith((".mjs", ".js", ".py", ".ts", ".cjs")):
                parts.append(f"script:{os.path.basename(a)}")
                break
        else:
            cmd = str(srv.get("command", "")).strip()
            if cmd:
                parts.append(f"cmd:{cmd}")
    env_keys = [k for k in (srv.get("env") or {}).keys() if _looks_secret_env_key(k)]
    if env_keys:
        parts.append(f"creds:{','.join(env_keys)}")
    return "__mcp__|" + "|".join(parts)


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


_PLATFORM_LABELS = {
    "webchat": "WebChat",
    "slack": "Slack",
    "discord": "Discord",
    "telegram": "Telegram",
    "whatsapp": "WhatsApp",
    "feishu": "飞书",
    "lark": "Lark",
    "wechat": "微信",
    "signal": "Signal",
    "imessage": "iMessage",
    "googlechat": "Google Chat",
    "msteams": "Microsoft Teams",
    "mattermost": "Mattermost",
    "matrix": "Matrix",
}


def _channel_label(key: str) -> str:
    k = str(key).lower()
    return _PLATFORM_LABELS.get(k, str(key).replace("_", " ").title())


def _channel_cred_keys(ch: dict) -> List[str]:
    """仅记录凭证字段名，绝不读取或存储值。"""
    out: List[str] = []
    for k, v in ch.items():
        if v in (None, "", [], {}):
            continue
        lk = str(k).lower()
        if any(t in lk for t in ("token", "secret", "key", "password", "credential")):
            out.append(str(k))
    return out


def _channel_purpose(label: str, ch: dict) -> str:
    parts: List[str] = []
    if ch.get("dmPolicy"):
        parts.append(f"DM 策略 {ch['dmPolicy']}")
    if ch.get("mode"):
        parts.append(f"模式 {ch['mode']}")
    creds = _channel_cred_keys(ch)
    if creds:
        parts.append(f"凭证引用：{', '.join(creds)}")
    suffix = f"（{'; '.join(parts)}）" if parts else ""
    return f"{label} IM 通道{suffix}"


def _channel_version_hint(ch: dict) -> Optional[str]:
    for key in ("mode", "dmPolicy"):
        val = ch.get(key)
        if val not in (None, ""):
            return str(val)
    return None


def discover_channels(
    agent_id: str,
    source: str,
    cfg: dict,
    cfg_path: str,
    *,
    roots: Tuple[str, ...] = ("channels",),
) -> List[Asset]:
    """从 Agent 主配置发现对外 IM 通道（OpenClaw channels.* / Hermes platforms.*）。"""
    out: List[Asset] = []
    seen: set[str] = set()

    for root in roots:
        section = cfg.get(root)
        if not isinstance(section, dict):
            continue
        for key, ch in section.items():
            if not isinstance(ch, dict) or not ch:
                continue
            safe_suffix = re.sub(r"[^\w-]", "-", str(key))
            cid = f"{agent_id}-channel-{root}-{safe_suffix}"
            if cid in seen:
                continue
            seen.add(cid)
            label = _channel_label(str(key))
            enabled = ch.get("enabled", True) is not False
            out.append(
                Asset(
                    id=cid,
                    agent_id=agent_id,
                    type=AssetType.CHANNEL.value,
                    name=label,
                    version=_channel_version_hint(ch),
                    status=AssetStatus.DISABLED.value if not enabled else AssetStatus.ENABLED.value,
                    purpose=_channel_purpose(label, ch),
                    source=source,
                    permissions=[
                        perm(
                            f"ch-{agent_id}-{safe_suffix}",
                            "network",
                            FindingSource.AGENT_CONFIG,
                            label,
                            Severity.MEDIUM,
                        )
                    ],
                    path=cfg_path,
                    config_key=f"{root}:{key}",
                    can_disable=True,
                    can_uninstall=False,
                    can_update=False,
                )
            )

    return out


"""OpenAI Codex Adapter：解析真机 ~/.codex 与项目 .codex/config.toml。

真实格式：
  ~/.codex/config.toml              model / mcp_servers / plugins / projects
  ~/.codex/skills/**/SKILL.md       用户与内置 Skill
  ~/.codex/rules/*.rules            规则配置
  ~/.codex/AGENTS.md                全局 Agent 指令
  <project>/.codex/config.toml      可信项目 MCP 覆盖（trust_level = trusted）
  <project>/AGENTS.md               项目级 Agent 指令
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Set, Tuple

from ..models import Agent, Asset, AssetStatus, AssetType, FindingSource, PermissionEntry, Severity
from . import parsers
from .base import AgentAdapter

ST = AssetStatus
AT = AssetType
SRC = FindingSource
S = Severity

CODEX_PKG = "@openai/codex"
CODEX_APP_CLI = "/Applications/Codex.app/Contents/Resources/codex"
CODEX_APP_INFO = "/Applications/Codex.app/Contents/Info.plist"
MAX_PROJECT_SCAN = 50
_SKIP_SKILL_DIRS = frozenset({".system"})
_TRUSTED_LEVELS = frozenset({"trusted", "true", "yes", "1"})


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", text.strip().lower())
    return s.strip("-") or "unknown"


def _format_version(val: Optional[str]) -> str:
    if not val:
        return ""
    s = str(val).strip().lstrip("vV")
    m = re.search(r"[0-9][\w.\-]*", s)
    return f"v{m.group(0)}" if m else ""


def _read_toml(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        import tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _codex_has_install(home: Optional[str]) -> bool:
    if not home or not os.path.isdir(home):
        return False
    markers = ("config.toml", "auth.json", "models_cache.json")
    return any(os.path.isfile(os.path.join(home, name)) for name in markers)


def _resolve_codex_cli() -> Optional[str]:
    from ..config import get_agent_bin

    for candidate in (get_agent_bin("codex"), shutil.which("codex")):
        if candidate and os.path.isfile(candidate):
            return candidate
    if os.path.isfile(CODEX_APP_CLI):
        return CODEX_APP_CLI
    return None


def resolve_codex_installed_version() -> str:
    """Codex 已安装版本：CLI --version → models_cache → macOS App → npm @openai/codex。"""
    cli = _resolve_codex_cli()
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
            match = re.search(r"([\d.]+(?:[.\-]\w+)*)", text)
            if match:
                formatted = _format_version(match.group(1))
                if formatted:
                    return formatted

    home = os.path.expanduser("~/.codex")
    cache_path = os.path.join(home, "models_cache.json")
    if os.path.isfile(cache_path):
        data = parsers.read_json(cache_path) or {}
        formatted = _format_version(data.get("client_version"))
        if formatted:
            return formatted

    if os.path.isfile(CODEX_APP_INFO):
        try:
            with open(CODEX_APP_INFO, "rb") as f:
                info = plistlib.load(f)
            formatted = _format_version(info.get("CFBundleShortVersionString"))
            if formatted:
                return formatted
        except (OSError, plistlib.InvalidFileException):
            pass

    # npm global install path heuristic
    npm_root = shutil.which("npm")
    if npm_root:
        try:
            proc = subprocess.run(
                [npm_root, "root", "-g"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            proc = None
        if proc and proc.returncode == 0:
            pkg_json = os.path.join(proc.stdout.strip(), CODEX_PKG, "package.json")
            data = parsers.read_json(pkg_json) or {}
            formatted = _format_version(data.get("version"))
            if formatted:
                return formatted
    return ""


def _trusted_projects(config: dict) -> List[str]:
    out: List[str] = []
    projects = config.get("projects") or {}
    if not isinstance(projects, dict):
        return out
    for path, meta in projects.items():
        if not path or not isinstance(meta, dict):
            continue
        level = str(meta.get("trust_level", "")).lower()
        if level in _TRUSTED_LEVELS:
            out.append(os.path.realpath(os.path.expanduser(str(path))))
    return out[:MAX_PROJECT_SCAN]


def _mcp_dedup_key(name: str, srv: dict) -> str:
    if srv.get("url"):
        return f"{name}|url|{srv.get('url')}"
    cmd = str(srv.get("command", ""))
    args = json.dumps(srv.get("args") or [], sort_keys=True)
    return f"{name}|{cmd}|{args}"


def _mcp_to_asset(
    agent_id: str,
    name: str,
    srv: dict,
    *,
    config_path: str,
    source: str,
    asset_prefix: str = "codex-mcp",
) -> Asset:
    cmd = str(srv.get("command", ""))
    args = [str(a) for a in (srv.get("args") or [])]
    url = str(srv.get("url") or "")
    enabled = srv.get("enabled", True) is not False
    if url:
        purpose = f"MCP · {name}（{url}）"
    else:
        detail = " ".join([cmd] + args).strip() or name
        purpose = f"MCP · {name}（{detail}）"
    env = srv.get("env") or {}
    cred_keys = list(env.keys())[:6]
    if cred_keys and not url:
        purpose = f"MCP · {name}（{cmd or 'stdio'}，需配置 {', '.join(cred_keys)}）"

    perms = parsers.perms_from_mcp_server(name, {"command": cmd or "http", "args": args})
    if url and not any(p.category == "网络" for p in perms):
        perms.append(
            parsers.perm(f"codex-mcp-{ _slug(name) }-network", "network", SRC.MCP, f"{name} MCP")
        )

    return Asset(
        id=f"{asset_prefix}-{_slug(name)}",
        agent_id=agent_id,
        type=AT.MCP.value,
        name=name,
        status=ST.ENABLED.value if enabled else ST.DISABLED.value,
        purpose=purpose,
        source=source,
        path=config_path,
        config_key=name,
        permissions=perms,
        can_disable=True,
        can_uninstall=False,
    )


class CodexAdapter(AgentAdapter):
    kind = "codex"

    def detect(self) -> Optional[Agent]:
        home = self.resolve_home()
        if not _codex_has_install(home):
            return None
        config = _read_toml(os.path.join(home, "config.toml")) if home else {}
        self._config = config
        self._home = home
        return Agent(
            id="codex",
            name="Codex",
            kind="codex",
            version=resolve_codex_installed_version(),
            description=self._description(config),
            permissions=self._default_permissions(config),
        )

    def _description(self, config: dict) -> str:
        model = str(config.get("model") or "").strip()
        if model:
            return f"Codex（模型：{model}）"
        return "Codex"

    def _default_permissions(self, config: dict) -> List[PermissionEntry]:
        out: List[PermissionEntry] = []
        seen: set[str] = set()

        def add(key: str, severity: Optional[Severity] = None) -> None:
            k = key.lower()
            if k in seen:
                return
            seen.add(k)
            out.append(parsers.perm(f"codex-default-{k}", k, SRC.AGENT_CONFIG, "Agent 默认", severity))

        add("network")
        if config.get("features", {}).get("memories"):
            add("knowledge")
        for _name, srv in (config.get("mcp_servers") or {}).items():
            if isinstance(srv, dict):
                for p in parsers.perms_from_mcp_server(str(_name), srv):
                    if p.id not in seen:
                        seen.add(p.id)
                        out.append(p)
        return out

    def discover_assets(self, agent: Agent) -> List[Asset]:
        home = self.resolve_home()
        if not home:
            return []
        config = getattr(self, "_config", None) or _read_toml(os.path.join(home, "config.toml"))
        assets: List[Asset] = []
        assets.extend(self._mcp_from_config(config, os.path.join(home, "config.toml")))
        assets.extend(self._project_assets(config))
        assets.extend(self._skills(home))
        assets.extend(self._rules(home))
        assets.extend(self._plugins(config))
        assets.extend(self._dependency())
        return self._dedupe_assets(assets)

    def _dedupe_assets(self, assets: List[Asset]) -> List[Asset]:
        seen: Set[str] = set()
        out: List[Asset] = []
        for asset in assets:
            if asset.id in seen:
                continue
            seen.add(asset.id)
            out.append(asset)
        return out

    def _mcp_from_config(self, config: dict, config_path: str) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        servers = config.get("mcp_servers") or {}
        if not isinstance(servers, dict):
            return out
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            key = _mcp_dedup_key(str(name), srv)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _mcp_to_asset(
                    "codex",
                    str(name),
                    srv,
                    config_path=config_path,
                    source="Codex",
                )
            )
        return out

    def _project_assets(self, config: dict) -> List[Asset]:
        out: List[Asset] = []
        for project_path in _trusted_projects(config):
            if not os.path.isdir(project_path):
                continue
            proj_config_path = os.path.join(project_path, ".codex", "config.toml")
            proj_config = _read_toml(proj_config_path)
            if proj_config:
                out.extend(
                    self._mcp_from_config(
                        proj_config,
                        proj_config_path,
                    )
                )
            agents_md = os.path.join(project_path, "AGENTS.md")
            if os.path.isfile(agents_md):
                out.append(
                    Asset(
                        id=f"codex-rule-{_slug(project_path)}-agents-md",
                        agent_id="codex",
                        type=AT.KNOWLEDGE.value,
                        name=f"AGENTS.md · {os.path.basename(project_path)}",
                        status=ST.ENABLED.value,
                        purpose="项目级 Agent 规则",
                        source="Codex",
                        path=agents_md,
                        can_disable=False,
                        can_uninstall=False,
                    )
                )
        return out

    def _skills(self, home: str) -> List[Asset]:
        out: List[Asset] = []
        skills_root = os.path.join(home, "skills")
        if not os.path.isdir(skills_root):
            return out
        for dirpath, dirnames, filenames in os.walk(skills_root):
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
            if "SKILL.md" not in filenames:
                continue
            rel = os.path.relpath(dirpath, skills_root)
            top = rel.split(os.sep)[0]
            if top in _SKIP_SKILL_DIRS:
                continue
            skill_path = os.path.join(dirpath, "SKILL.md")
            fm = parsers.parse_skill_frontmatter(skill_path)
            name = str((fm or {}).get("name") or os.path.basename(dirpath))
            slug = _slug(name)
            perms = parsers.perms_from_skill_frontmatter(slug, name, fm or {})
            out.append(
                Asset(
                    id=f"codex-skill-{_slug(rel)}",
                    agent_id="codex",
                    type=AT.SKILL.value,
                    name=name,
                    status=ST.ENABLED.value,
                    purpose="用户 Skill",
                    source="Codex",
                    path=skill_path,
                    skill_scope="user",
                    permissions=perms,
                    can_disable=True,
                    can_uninstall=True,
                )
            )
        return out

    def _rules(self, home: str) -> List[Asset]:
        out: List[Asset] = []
        agents_md = os.path.join(home, "AGENTS.md")
        if os.path.isfile(agents_md) and os.path.getsize(agents_md) > 0:
            out.append(
                Asset(
                    id="codex-rule-agents-md",
                    agent_id="codex",
                    type=AT.KNOWLEDGE.value,
                    name="AGENTS.md",
                    status=ST.ENABLED.value,
                    purpose="全局 Agent 规则",
                    source="Codex",
                    path=agents_md,
                    can_disable=False,
                    can_uninstall=False,
                )
            )
        rules_dir = os.path.join(home, "rules")
        if os.path.isdir(rules_dir):
            for fname in sorted(os.listdir(rules_dir)):
                if not fname.endswith(".rules"):
                    continue
                path = os.path.join(rules_dir, fname)
                out.append(
                    Asset(
                        id=f"codex-rule-{_slug(fname)}",
                        agent_id="codex",
                        type=AT.KNOWLEDGE.value,
                        name=f"rules/{fname}",
                        status=ST.ENABLED.value,
                        purpose="Codex 规则配置",
                        source="Codex",
                        path=path,
                        can_disable=False,
                        can_uninstall=False,
                    )
                )
        return out

    def _plugins(self, config: dict) -> List[Asset]:
        out: List[Asset] = []
        plugins = config.get("plugins") or {}
        if not isinstance(plugins, dict):
            return out
        for name, meta in plugins.items():
            enabled = True
            if isinstance(meta, dict):
                enabled = meta.get("enabled", True) is not False
            out.append(
                Asset(
                    id=f"codex-plugin-{_slug(str(name))}",
                    agent_id="codex",
                    type=AT.KNOWLEDGE.value,
                    name=str(name),
                    status=ST.ENABLED.value if enabled else ST.DISABLED.value,
                    purpose="Codex 插件",
                    source="Codex",
                    can_disable=True,
                    can_uninstall=False,
                )
            )
        return out

    def _dependency(self) -> List[Asset]:
        ver = resolve_codex_installed_version()
        if not ver:
            return []
        cli = _resolve_codex_cli()
        install_path = None
        if cli:
            install_path = os.path.dirname(cli)
        return [
            Asset(
                id="codex-dep-codex-cli",
                agent_id="codex",
                type=AT.DEPENDENCY.value,
                name=CODEX_PKG,
                version=ver,
                status=ST.ENABLED.value,
                purpose="Codex CLI 主程序",
                source="Codex",
                ecosystem="npm",
                manager="npm",
                install_path=install_path,
                package_name=CODEX_PKG,
                can_update=True,
                can_uninstall=True,
                can_disable=False,
            )
        ]

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = self.resolve_home()
        if not home:
            return []
        config = getattr(self, "_config", None) or _read_toml(os.path.join(home, "config.toml"))
        targets: List[Tuple[str, str]] = []
        seen: Set[str] = set()

        def add(path: Optional[str], source: str) -> None:
            if not path or not os.path.isfile(path):
                return
            real = os.path.realpath(path)
            if real in seen:
                return
            seen.add(real)
            targets.append((real, source))

        add(os.path.join(home, "config.toml"), SRC.AGENT_CONFIG.value)
        add(os.path.join(home, "AGENTS.md"), SRC.KNOWLEDGE.value)
        rules_dir = os.path.join(home, "rules")
        if os.path.isdir(rules_dir):
            for fname in os.listdir(rules_dir):
                if fname.endswith(".rules"):
                    add(os.path.join(rules_dir, fname), SRC.KNOWLEDGE.value)
        skills_root = os.path.join(home, "skills")
        if os.path.isdir(skills_root):
            for dirpath, dirnames, filenames in os.walk(skills_root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_SKILL_DIRS]
                if "SKILL.md" in filenames:
                    add(os.path.join(dirpath, "SKILL.md"), SRC.SKILL.value)
        for project_path in _trusted_projects(config):
            add(os.path.join(project_path, "AGENTS.md"), SRC.KNOWLEDGE.value)
            add(os.path.join(project_path, ".codex", "config.toml"), SRC.AGENT_CONFIG.value)
        return targets

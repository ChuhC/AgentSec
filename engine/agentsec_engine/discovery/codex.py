"""OpenAI Codex Adapter：解析真机 ~/.codex 与项目 .codex/config.toml。

真实格式：
  ~/.codex/config.toml              model / mcp_servers / plugins / projects
  ~/.codex/skills/**/SKILL.md       用户 Skill 与 .system 内置 Skill
  ~/.codex/skills/**/SKILL.md       用户 Skill 与 .system 内置 Skill
  <project>/.codex/config.toml      可信项目 MCP 覆盖（trust_level = trusted）
  ~/.codex/plugins/cache/**         已启用插件的 Skill / Hooks / MCP
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import urllib.parse
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
_SKIP_PLUGIN_DIRS = frozenset({"node_modules", ".git", "marketplaces"})
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


def _split_plugin_id(plugin_id: str) -> Tuple[str, str]:
    if "@" in plugin_id:
        name, marketplace = plugin_id.split("@", 1)
        return name.strip(), marketplace.strip()
    return plugin_id.strip(), plugin_id.strip()


def _enabled_codex_plugins(config: dict) -> List[Tuple[str, bool]]:
    plugins = config.get("plugins") or {}
    if not isinstance(plugins, dict):
        return []
    out: List[Tuple[str, bool]] = []
    for plugin_id, meta in plugins.items():
        enabled = True
        if isinstance(meta, dict):
            enabled = meta.get("enabled", True) is not False
        out.append((str(plugin_id), enabled))
    return out


def _resolve_codex_plugin_cache_dir(home: str, plugin_id: str) -> Optional[str]:
    name, marketplace = _split_plugin_id(plugin_id)
    candidates = [
        os.path.join(home, "plugins", "cache", marketplace, name),
        os.path.join(home, "plugins", "cache", name, marketplace),
    ]
    for base in candidates:
        if not os.path.isdir(base):
            continue
        versions = [
            d
            for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d)) and not d.startswith(".")
        ]
        if not versions:
            continue
        versions.sort(
            key=lambda v: tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)),
            reverse=True,
        )
        return os.path.join(base, versions[0])
    return None


def _codex_plugin_manifest(root: str) -> dict:
    return parsers.read_json(os.path.join(root, ".codex-plugin", "plugin.json")) or {}


def _codex_plugin_hooks_path(root: str) -> Optional[str]:
    manifest = _codex_plugin_manifest(root)
    hooks = manifest.get("hooks")
    if isinstance(hooks, str):
        fp = os.path.join(root, hooks.lstrip("./"))
        if os.path.isfile(fp):
            return fp
    for candidate in (os.path.join(root, "hooks.json"), os.path.join(root, "hooks", "hooks.json")):
        if os.path.isfile(candidate):
            return candidate
    return None


def _hooks_use_shell(hooks_data: dict) -> bool:
    hooks = hooks_data.get("hooks") or {}
    if not isinstance(hooks, dict):
        return False
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            if not isinstance(inner, list):
                continue
            for hook in inner:
                if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command"):
                    return True
    return False


def _load_codex_plugin_mcp(root: str) -> Dict[str, dict]:
    manifest = _codex_plugin_manifest(root)
    mcp_field = manifest.get("mcpServers")
    if isinstance(mcp_field, dict):
        return {str(k): v for k, v in mcp_field.items() if isinstance(v, dict)}
    for name in (".mcp.json", "mcp.json"):
        path = os.path.join(root, name)
        data = parsers.read_json(path) or {}
        servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else data
        if isinstance(servers, dict):
            return {str(k): v for k, v in servers.items() if isinstance(v, dict)}
    return {}


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
        parsed = urllib.parse.urlsplit(url)
        safe_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.hostname or "", parsed.path, "", "")
        )
        purpose = f"MCP · {name}（{safe_url or '远程服务'}）"
    else:
        package = parsers.parse_mcp_npm_package(
            {"command": cmd, "args": args}
        )
        detail = package or os.path.basename(cmd) or name
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
        assets.extend(self._plugins(config, home))
        assets.extend(self._plugin_skills(home, config))
        assets.extend(self._plugin_hooks(home, config))
        assets.extend(self._plugin_mcp(home, config))
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
            if not self.path_in_scope(project_path) or not os.path.isdir(project_path):
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
            is_system = top == ".system"
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
                    purpose="内置 Skill" if is_system else "用户 Skill",
                    source="Codex",
                    path=skill_path,
                    skill_scope="global" if is_system else "user",
                    permissions=perms,
                    can_disable=False,
                    can_uninstall=False,
                )
            )
        return out

    def _plugins(self, config: dict, home: str) -> List[Asset]:
        out: List[Asset] = []
        for plugin_id, enabled in _enabled_codex_plugins(config):
            root = _resolve_codex_plugin_cache_dir(home, plugin_id)
            manifest = _codex_plugin_manifest(root) if root else {}
            display = str(manifest.get("name") or plugin_id)
            version = str(manifest.get("version") or "") or None
            purpose = str(manifest.get("description") or "") or "Codex 插件"
            if len(purpose) > 120:
                purpose = purpose[:117] + "..."
            out.append(
                Asset(
                    id=f"codex-plugin-{_slug(plugin_id)}",
                    agent_id="codex",
                    type=AT.PLUGIN.value,
                    name=display,
                    version=version,
                    status=ST.ENABLED.value if enabled else ST.DISABLED.value,
                    purpose=purpose,
                    source="Codex",
                    path=root,
                    config_key=plugin_id,
                    can_disable=False,
                    can_uninstall=False,
                )
            )
        return out

    def _plugin_skills(self, home: str, config: dict) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        for plugin_id, enabled in _enabled_codex_plugins(config):
            if not enabled:
                continue
            root = _resolve_codex_plugin_cache_dir(home, plugin_id)
            if not root:
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_PLUGIN_DIRS]
                if "SKILL.md" not in filenames:
                    continue
                skill_path = os.path.join(dirpath, "SKILL.md")
                rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
                fm = parsers.parse_skill_frontmatter(skill_path)
                name = str((fm or {}).get("name") or os.path.basename(dirpath))
                asset_id = f"codex-plugin-skill-{_slug(plugin_id)}-{_slug(rel)}"
                if asset_id in seen:
                    continue
                seen.add(asset_id)
                perms = parsers.perms_from_skill_frontmatter(_slug(name), name, fm or {})
                purpose = str((fm or {}).get("description") or "") or "插件 Skill"
                out.append(
                    Asset(
                        id=asset_id,
                        agent_id="codex",
                        type=AT.SKILL.value,
                        name=name,
                        version=str((fm or {}).get("version") or "") or None,
                        status=ST.ENABLED.value,
                        purpose=f"{purpose} · {plugin_id}",
                        source="Codex",
                        path=skill_path,
                        config_key=plugin_id,
                        skill_scope="global",
                        permissions=perms,
                        can_disable=False,
                        can_uninstall=False,
                    )
                )
        return out

    def _plugin_hooks(self, home: str, config: dict) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        for plugin_id, enabled in _enabled_codex_plugins(config):
            if not enabled:
                continue
            root = _resolve_codex_plugin_cache_dir(home, plugin_id)
            if not root:
                continue
            hooks_path = _codex_plugin_hooks_path(root)
            if not hooks_path:
                continue
            asset_id = f"codex-plugin-hook-{_slug(plugin_id)}"
            if asset_id in seen:
                continue
            seen.add(asset_id)
            manifest = _codex_plugin_manifest(root)
            hooks_data = parsers.read_json(hooks_path) or {}
            perms: List[PermissionEntry] = []
            if _hooks_use_shell(hooks_data):
                label = str(manifest.get("name") or plugin_id)
                perms.append(
                    parsers.perm(
                        f"codex-plugin-hook-{_slug(plugin_id)}-shell",
                        "shell",
                        SRC.AGENT_CONFIG,
                        f"Hooks · {label}",
                        S.HIGH,
                    )
                )
            out.append(
                Asset(
                    id=asset_id,
                    agent_id="codex",
                    type=AT.HOOK.value,
                    name=f"hooks · {manifest.get('name') or plugin_id}",
                    version=str(manifest.get("version") or "") or None,
                    status=ST.ENABLED.value,
                    purpose=f"插件生命周期 Hooks · {plugin_id}",
                    source="Codex",
                    path=hooks_path,
                    config_key=plugin_id,
                    permissions=perms,
                    can_disable=False,
                    can_uninstall=False,
                )
            )
        return out

    def _plugin_mcp(self, home: str, config: dict) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        for plugin_id, enabled in _enabled_codex_plugins(config):
            if not enabled:
                continue
            root = _resolve_codex_plugin_cache_dir(home, plugin_id)
            if not root:
                continue
            manifest = _codex_plugin_manifest(root)
            mcp_path = os.path.join(root, ".mcp.json")
            if not os.path.isfile(mcp_path):
                mcp_path = root
            for name, srv in _load_codex_plugin_mcp(root).items():
                key = _mcp_dedup_key(str(name), srv)
                if key in seen:
                    continue
                seen.add(key)
                asset = _mcp_to_asset(
                    "codex",
                    str(name),
                    srv,
                    config_path=mcp_path,
                    source="Codex",
                    asset_prefix="codex-mcp-plugin",
                )
                asset.version = str(manifest.get("version") or "") or None
                asset.config_key = plugin_id
                asset.purpose = f"{asset.purpose} · {plugin_id}"
                asset.can_disable = False
                asset.can_uninstall = False
                out.append(asset)
        return out

    def _dependency(self) -> List[Asset]:
        if self.scope_path is not None:
            return []
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
                version=ver.lstrip("vV"),
                status=ST.ENABLED.value,
                purpose="Codex CLI 主程序",
                source="Codex",
                ecosystem="npm",
                manager="npm",
                install_path=install_path,
                package_name=CODEX_PKG,
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
            if (
                not path
                or not self.path_in_scope(path)
                or not os.path.isfile(path)
            ):
                return
            real = os.path.realpath(path)
            if real in seen:
                return
            seen.add(real)
            targets.append((real, source))

        add(os.path.join(home, "config.toml"), SRC.AGENT_CONFIG.value)
        add(os.path.join(home, "AGENTS.md"), SRC.RULE.value)
        rules_dir = os.path.join(home, "rules")
        if os.path.isdir(rules_dir):
            for fname in os.listdir(rules_dir):
                if fname.endswith(".rules"):
                    add(os.path.join(rules_dir, fname), SRC.RULE.value)
        memories_dir = os.path.join(home, "memories")
        if os.path.isdir(memories_dir):
            for fname in os.listdir(memories_dir):
                if fname.startswith("."):
                    continue
                path = os.path.join(memories_dir, fname)
                if os.path.isfile(path) and fname.endswith((".md", ".txt", ".json")):
                    add(path, SRC.AGENT_CONFIG.value)
        skills_root = os.path.join(home, "skills")
        if os.path.isdir(skills_root):
            for dirpath, dirnames, filenames in os.walk(skills_root):
                dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
                if "SKILL.md" in filenames:
                    add(os.path.join(dirpath, "SKILL.md"), SRC.SKILL.value)
        for project_path in _trusted_projects(config):
            if not self.path_in_scope(project_path):
                continue
            add(os.path.join(project_path, "AGENTS.md"), SRC.RULE.value)
            add(os.path.join(project_path, ".codex", "config.toml"), SRC.AGENT_CONFIG.value)
        for plugin_id, enabled in _enabled_codex_plugins(config):
            if not enabled:
                continue
            root = _resolve_codex_plugin_cache_dir(home, plugin_id)
            if not root:
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_PLUGIN_DIRS]
                if "SKILL.md" in filenames:
                    add(os.path.join(dirpath, "SKILL.md"), SRC.SKILL.value)
            hooks_path = _codex_plugin_hooks_path(root)
            if hooks_path:
                add(hooks_path, SRC.AGENT_CONFIG.value)
            for name in (".mcp.json", "mcp.json"):
                add(os.path.join(root, name), SRC.MCP.value)
        return targets

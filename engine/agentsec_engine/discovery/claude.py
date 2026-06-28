"""Claude Code Adapter：解析真机 ~/.claude 与 ~/.claude.json。

真实格式：
  ~/.claude/settings.json[.local.json]  env / model / enabledPlugins 等
  ~/.claude.json                        mcpServers、projects、allowedTools 等
  ~/.claude/skills/**/SKILL.md          用户 Skill
  ~/.claude/plugins/cache/**            插件 Skill / Hooks / bundled MCP
  <project>/.mcp.json、CLAUDE.md、.claude/rules/
"""

from __future__ import annotations

import json
import os
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

CLAUDE_JSON_MAX_BYTES = 512 * 1024
MAX_PROJECT_SCAN = 50
SKIP_PLUGIN_DIRS = frozenset({"marketplaces", "node_modules", ".git"})
_PROJECT_RULE_FILES = ("CLAUDE.md", "AGENTS.md")
_CLAUDE_CODE_PKG = "@anthropic-ai/claude-code"
_NETWORK_ENV_HINTS = ("proxy", "url", "api", "host", "port", "token", "key", "endpoint")


def claude_json_path() -> str:
    return os.path.expanduser("~/.claude.json")


def _format_version(val: Optional[str]) -> str:
    if not val:
        return ""
    s = str(val).strip().lstrip("vV")
    m = re.search(r"[0-9][\w.\-]*", s)
    return f"v{m.group(0)}" if m else ""


def resolve_claude_installed_version(claude_json: Optional[dict] = None) -> str:
    """Claude Code 已安装版本：CLI --version → claude.json → cache/changelog.md。"""
    from ..config import get_agent_bin

    cli = get_agent_bin("claude") or shutil.which("claude")
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

    cj = claude_json if claude_json is not None else (parsers.read_json(claude_json_path()) or {})
    for key in ("lastReleaseNotesSeen", "lastOnboardingVersion", "version"):
        formatted = _format_version(cj.get(key))
        if formatted:
            return formatted

    changelog = cj.get("changelog")
    if isinstance(changelog, list) and changelog:
        last = changelog[-1]
        if isinstance(last, dict):
            formatted = _format_version(last.get("version"))
            if formatted:
                return formatted

    home = os.path.expanduser("~/.claude")
    changelog_path = os.path.join(home, "cache", "changelog.md")
    if os.path.isfile(changelog_path):
        try:
            with open(changelog_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.match(r"^##\s+([\d.]+(?:[.\-]\w+)*)", line.strip())
                    if m:
                        formatted = _format_version(m.group(1))
                        if formatted:
                            return formatted
        except OSError:
            pass
    return ""


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", text.strip().lower())
    return s.strip("-") or "unknown"


def _mcp_dedup_key(name: str, srv: dict) -> str:
    cmd = str(srv.get("command", ""))
    args = json.dumps(srv.get("args") or [], sort_keys=True)
    return f"{name}|{cmd}|{args}"


def _env_implies_network(env: dict) -> bool:
    if not env:
        return False
    for key in env:
        kl = key.lower()
        if any(h in kl for h in _NETWORK_ENV_HINTS):
            return True
    return False


def _parse_mcp_document(data: dict) -> Dict[str, dict]:
    """Normalize MCP JSON (.mcp.json or inline mcpServers)."""
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("mcpServers"), dict):
        return {str(k): v for k, v in data["mcpServers"].items() if isinstance(v, dict)}
    if isinstance(data.get("servers"), dict):
        return {str(k): v for k, v in data["servers"].items() if isinstance(v, dict)}
    out: Dict[str, dict] = {}
    for key, val in data.items():
        if key in ("mcpServers", "servers", "$schema"):
            continue
        if isinstance(val, dict) and any(k in val for k in ("command", "type", "url", "args")):
            out[str(key)] = val
    return out


def _iter_projects(claude_json: dict) -> List[Tuple[str, dict]]:
    projects = claude_json.get("projects") or {}
    if not isinstance(projects, dict):
        return []
    items: List[Tuple[str, dict]] = []
    for path, proj in list(projects.items())[:MAX_PROJECT_SCAN]:
        items.append((str(path), proj if isinstance(proj, dict) else {}))
    return items


def _mcp_enabled(proj: Optional[dict], name: str, srv: dict) -> bool:
    if srv.get("enabled") is False:
        return False
    if not proj:
        return True
    disabled = proj.get("disabledMcpjsonServers") or []
    if isinstance(disabled, list) and name in disabled:
        return False
    enabled = proj.get("enabledMcpjsonServers") or []
    if isinstance(enabled, list) and enabled:
        return name in enabled
    return True


def _split_plugin_id(plugin_id: str) -> Tuple[str, str]:
    if "@" in plugin_id:
        name, marketplace = plugin_id.split("@", 1)
        return name.strip(), marketplace.strip()
    return plugin_id.strip(), plugin_id.strip()


def _enabled_plugin_ids(settings: dict) -> List[str]:
    enabled = settings.get("enabledPlugins") or {}
    if not isinstance(enabled, dict):
        return []
    return [str(pid) for pid, on in enabled.items() if on is not False]


def _plugin_matches_path(plugin_id: str, rel: str, skill_name: str) -> bool:
    """plugin_id 形如 name@marketplace；cache 路径为 marketplace/name/version/…。"""
    name_part, market_part = _split_plugin_id(plugin_id)
    rel_l = rel.lower()
    skill_l = str(skill_name).lower()
    return (
        market_part.lower() in rel_l
        or name_part.lower() in rel_l
        or name_part.lower() in skill_l
    )


def _resolve_plugin_cache_dir(home: str, plugin_id: str) -> Optional[str]:
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
        versions.sort(key=lambda v: tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)), reverse=True)
        return os.path.join(base, versions[0])
    return None


def _plugin_manifest(root: str) -> dict:
    return parsers.read_json(os.path.join(root, ".claude-plugin", "plugin.json")) or {}


def _plugin_hooks_path(root: str) -> Optional[str]:
    manifest = _plugin_manifest(root)
    hooks = manifest.get("hooks")
    if isinstance(hooks, str):
        rel = hooks.lstrip("./")
        fp = os.path.join(root, rel)
        return fp if os.path.isfile(fp) else None
    default = os.path.join(root, "hooks", "hooks.json")
    return default if os.path.isfile(default) else None


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


def _load_plugin_mcp_configs(root: str) -> Dict[str, dict]:
    manifest = _plugin_manifest(root)
    mcp_field = manifest.get("mcpServers")
    if isinstance(mcp_field, dict):
        return _parse_mcp_document({"mcpServers": mcp_field})
    if isinstance(mcp_field, str):
        rel = mcp_field.lstrip("./")
        fp = os.path.join(root, rel)
        if os.path.isfile(fp):
            return _parse_mcp_document(parsers.read_json(fp) or {})
    default = os.path.join(root, ".mcp.json")
    if os.path.isfile(default):
        return _parse_mcp_document(parsers.read_json(default) or {})
    return {}


def _claude_code_install_path() -> Optional[str]:
    cli = shutil.which("claude")
    if not cli:
        return None
    real = os.path.realpath(cli)
    marker = os.path.join("node_modules", _CLAUDE_CODE_PKG)
    idx = real.find(marker)
    if idx >= 0:
        return real[: idx + len(marker)]
    parent = os.path.dirname(real)
    for _ in range(6):
        pkg = os.path.join(parent, "node_modules", _CLAUDE_CODE_PKG)
        if os.path.isdir(pkg):
            return pkg
        parent = os.path.dirname(parent)
    return None


class ClaudeAdapter(AgentAdapter):
    kind = "claude"

    def _settings_path(self, home: Optional[str]) -> Optional[str]:
        if not home:
            return None
        p = os.path.join(home, "settings.json")
        return p if os.path.isfile(p) else None

    def _present(self) -> Tuple[Optional[str], bool]:
        home = self.resolve_home()
        has_json = os.path.isfile(claude_json_path())
        if home or has_json:
            return home, has_json
        return None, False

    def detect(self) -> Optional[Agent]:
        home, has_json = self._present()
        if not home and not has_json:
            return None
        settings = parsers.read_json(self._settings_path(home) or "") or {}
        claude_json = parsers.read_json(claude_json_path()) or {}
        if not home and not settings and not claude_json:
            return None
        self._home = home
        self._settings = settings
        self._claude_json = claude_json
        return Agent(
            id="claude",
            name="Claude Code",
            kind="claude",
            version=self._version(settings, claude_json),
            listen_ports=[],
            enabled=True,
            description=self._description(settings),
            permissions=self._agent_perms(settings)
            + self._project_tool_perms(claude_json),
        )

    def _version(self, settings: dict, claude_json: dict) -> str:
        return resolve_claude_installed_version(claude_json)

    def _description(self, settings: dict) -> str:
        model = settings.get("model") or settings.get("defaultModel") or ""
        if model:
            return f"Claude Code（模型：{model}）"
        return "Claude Code"

    def _agent_perms(self, settings: dict) -> List[PermissionEntry]:
        out: List[PermissionEntry] = []
        if settings.get("skipDangerousModePermissionPrompt"):
            out.append(parsers.perm("a-c-shell", "shell", SRC.AGENT_CONFIG, "Agent 默认", S.HIGH))
        env = settings.get("env") or {}
        if _env_implies_network(env):
            out.append(parsers.perm("a-c-net", "network", SRC.AGENT_CONFIG, "Agent 默认"))
        enabled = settings.get("enabledPlugins") or {}
        if isinstance(enabled, dict) and enabled:
            out.append(
                parsers.perm(
                    "a-c-tools",
                    "tool",
                    SRC.AGENT_CONFIG,
                    f"已启用 {len(enabled)} 个插件",
                )
            )
        return out

    def _project_tool_perms(self, claude_json: dict) -> List[PermissionEntry]:
        out: List[PermissionEntry] = []
        for project_path, proj in _iter_projects(claude_json):
            tools = proj.get("allowedTools") or []
            if not isinstance(tools, list) or not tools:
                continue
            label = f"项目 · {os.path.basename(project_path.rstrip(os.sep)) or project_path}"
            for idx, tool in enumerate(tools):
                name = str(tool).strip()
                if not name:
                    continue
                out.append(
                    parsers.perm(
                        f"claude-proj-{ _slug(project_path) }-{idx}",
                        "tool",
                        SRC.AGENT_CONFIG,
                        label,
                    )
                )
        return out

    def discover_assets(self, agent: Agent) -> List[Asset]:
        home = getattr(self, "_home", None) or self.resolve_home()
        settings = getattr(self, "_settings", None)
        if settings is None:
            settings = parsers.read_json(self._settings_path(home) or "") or {}
        claude_json = getattr(self, "_claude_json", None)
        if claude_json is None:
            claude_json = parsers.read_json(claude_json_path()) or {}
        return (
            self._mcp(claude_json)
            + self._plugin_mcp(home, settings)
            + self._hooks(home, settings)
            + self._skills(home, settings)
            + self._user_skills(home)
            + self._project_rules(claude_json)
            + self._marketplaces(home, settings)
            + self._deps()
        )

    def _mcp(self, claude_json: dict) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        cj_path = claude_json_path()

        def add_mcp(
            name: str,
            srv: dict,
            *,
            project: Optional[str] = None,
            proj_meta: Optional[dict] = None,
            config_path: Optional[str] = None,
            source_note: Optional[str] = None,
        ) -> None:
            if not isinstance(srv, dict):
                return
            key = _mcp_dedup_key(name, srv)
            if key in seen:
                return
            seen.add(key)
            perms = parsers.perms_from_mcp_server(name, srv)
            purpose = parsers.describe_mcp_purpose(name, srv)
            if project:
                purpose = f"{purpose}|project:{project}"
            if source_note:
                purpose = f"{purpose}|{source_note}"
            enabled = _mcp_enabled(proj_meta, name, srv)
            out.append(
                Asset(
                    id=f"claude-mcp-{_slug(key)}",
                    agent_id="claude",
                    type=AT.MCP.value,
                    name=name,
                    version=str(srv.get("version", "")) or None,
                    status=ST.DISABLED.value if not enabled else ST.ENABLED.value,
                    purpose=purpose,
                    source="Claude Code",
                    permissions=perms,
                    path=config_path or (cj_path if not project else project),
                    config_key=name,
                    can_disable=False,
                    can_uninstall=False,
                    can_update=False,
                )
            )

        for name, srv in (claude_json.get("mcpServers") or {}).items():
            add_mcp(str(name), srv)

        for project_path, proj in _iter_projects(claude_json):
            for name, srv in (proj.get("mcpServers") or {}).items():
                add_mcp(str(name), srv, project=project_path, proj_meta=proj)
            mcp_path = os.path.join(project_path, ".mcp.json")
            if os.path.isfile(mcp_path):
                for name, srv in _parse_mcp_document(parsers.read_json(mcp_path) or {}).items():
                    add_mcp(
                        str(name),
                        srv,
                        project=project_path,
                        proj_meta=proj,
                        config_path=mcp_path,
                        source_note="file:.mcp.json",
                    )

        return out

    def _plugin_mcp(self, home: Optional[str], settings: dict) -> List[Asset]:
        if not home:
            return []
        enabled_plugins = settings.get("enabledPlugins") or {}
        if not isinstance(enabled_plugins, dict):
            return []
        out: List[Asset] = []
        seen: Set[str] = set()

        for plugin_id in enabled_plugins:
            if enabled_plugins.get(plugin_id) is False:
                continue
            root = _resolve_plugin_cache_dir(home, str(plugin_id))
            if not root:
                continue
            manifest = _plugin_manifest(root)
            mcp_path = None
            mcp_field = manifest.get("mcpServers")
            if isinstance(mcp_field, str):
                mcp_path = os.path.join(root, mcp_field.lstrip("./"))
            elif os.path.isfile(os.path.join(root, ".mcp.json")):
                mcp_path = os.path.join(root, ".mcp.json")

            for name, srv in _load_plugin_mcp_configs(root).items():
                key = _mcp_dedup_key(name, srv)
                if key in seen:
                    continue
                seen.add(key)
                perms = parsers.perms_from_mcp_server(name, srv)
                purpose = parsers.describe_mcp_purpose(name, srv)
                purpose = f"{purpose}|plugin:{plugin_id}"
                out.append(
                    Asset(
                        id=f"claude-mcp-plugin-{_slug(key)}",
                        agent_id="claude",
                        type=AT.MCP.value,
                        name=name,
                        version=str(manifest.get("version", "")) or None,
                        status=ST.ENABLED.value,
                        purpose=purpose,
                        source="Claude Code",
                        permissions=perms,
                        path=mcp_path or root,
                        config_key=str(plugin_id),
                        can_disable=False,
                        can_uninstall=False,
                        can_update=False,
                    )
                )
        return out

    def _hooks(self, home: Optional[str], settings: dict) -> List[Asset]:
        if not home:
            return []
        enabled_plugins = settings.get("enabledPlugins") or {}
        if not isinstance(enabled_plugins, dict):
            return []
        out: List[Asset] = []
        seen: Set[str] = set()

        for plugin_id in enabled_plugins:
            if enabled_plugins.get(plugin_id) is False:
                continue
            root = _resolve_plugin_cache_dir(home, str(plugin_id))
            if not root:
                continue
            hooks_path = _plugin_hooks_path(root)
            if not hooks_path:
                continue
            slug = _slug(str(plugin_id))
            asset_id = f"claude-hook-{slug}"
            if asset_id in seen:
                continue
            seen.add(asset_id)
            hooks_data = parsers.read_json(hooks_path) or {}
            manifest = _plugin_manifest(root)
            perms: List[PermissionEntry] = []
            if _hooks_use_shell(hooks_data):
                perms.append(
                    parsers.perm(
                        f"claude-hook-{slug}-shell",
                        "shell",
                        SRC.AGENT_CONFIG,
                        f"Hooks · {manifest.get('name') or plugin_id}",
                        S.HIGH,
                    )
                )
            out.append(
                Asset(
                    id=asset_id,
                    agent_id="claude",
                    type=AT.HOOK.value,
                    name=f"hooks · {manifest.get('name') or plugin_id}",
                    version=str(manifest.get("version", "")) or None,
                    status=ST.ENABLED.value,
                    purpose="插件生命周期 Hooks",
                    source="Claude Code",
                    permissions=perms,
                    path=hooks_path,
                    config_key=str(plugin_id),
                    can_disable=False,
                    can_uninstall=False,
                    can_update=False,
                )
            )
        return out

    def _user_skills(self, home: Optional[str]) -> List[Asset]:
        if not home:
            return []
        skills_dir = os.path.join(home, "skills")
        if not os.path.isdir(skills_dir):
            return []
        out: List[Asset] = []
        for root, _dirs, files in os.walk(skills_dir):
            if "SKILL.md" not in files:
                continue
            md = os.path.join(root, "SKILL.md")
            fm = parsers.parse_skill_frontmatter(md)
            rel = os.path.relpath(root, skills_dir).replace(os.sep, "/")
            name = fm.get("name") or os.path.basename(root)
            slug = _slug(rel)
            perms = parsers.perms_from_skill_frontmatter(slug, str(name), fm)
            out.append(
                Asset(
                    id=f"claude-skill-user-{slug}",
                    agent_id="claude",
                    type=AT.SKILL.value,
                    name=str(name),
                    version=str(fm.get("version", "")) or None,
                    status=ST.ENABLED.value,
                    purpose=str(fm.get("description", "")) or "用户 Skill",
                    source="Claude Code",
                    skill_scope="user",
                    permissions=perms,
                    path=md,
                    can_disable=False,
                    can_uninstall=False,
                    can_update=False,
                )
            )
        out.sort(key=lambda a: a.name.lower())
        return out

    def _project_rules(self, claude_json: dict) -> List[Asset]:
        out: List[Asset] = []
        seen: Set[str] = set()
        for project_path, _proj in _iter_projects(claude_json):
            proj_name = os.path.basename(project_path.rstrip(os.sep)) or project_path
            for fname in _PROJECT_RULE_FILES:
                fp = os.path.join(project_path, fname)
                if not os.path.isfile(fp):
                    continue
                asset_id = f"claude-rule-{_slug(project_path)}-{_slug(fname)}"
                if asset_id in seen:
                    continue
                seen.add(asset_id)
                out.append(
                    Asset(
                        id=asset_id,
                        agent_id="claude",
                        type=AT.KNOWLEDGE.value,
                        name=f"{fname} · {proj_name}",
                        version=None,
                        status=ST.ENABLED.value,
                        purpose="项目级 Agent 规则",
                        source="Claude Code",
                        permissions=[],
                        path=fp,
                        can_disable=False,
                        can_uninstall=False,
                        can_update=False,
                    )
                )
            rules_dir = os.path.join(project_path, ".claude", "rules")
            if os.path.isdir(rules_dir):
                for root, _dirs, files in os.walk(rules_dir):
                    for fname in files:
                        if not fname.endswith(".md"):
                            continue
                        fp = os.path.join(root, fname)
                        rel = os.path.relpath(fp, rules_dir).replace(os.sep, "/")
                        asset_id = f"claude-rule-{_slug(project_path)}-{_slug(rel)}"
                        if asset_id in seen:
                            continue
                        seen.add(asset_id)
                        out.append(
                            Asset(
                                id=asset_id,
                                agent_id="claude",
                                type=AT.KNOWLEDGE.value,
                                name=f".claude/rules/{rel} · {proj_name}",
                                version=None,
                                status=ST.ENABLED.value,
                                purpose="项目 Cursor/Claude 规则",
                                source="Claude Code",
                                permissions=[],
                                path=fp,
                                can_disable=False,
                                can_uninstall=False,
                                can_update=False,
                            )
                        )
        return out

    def _deps(self) -> List[Asset]:
        ver = resolve_claude_installed_version()
        if not ver:
            return []
        norm = ver.lstrip("vV")
        install_path = _claude_code_install_path()
        return [
            Asset(
                id="claude-dep-claude-code",
                agent_id="claude",
                type=AT.DEPENDENCY.value,
                name=_CLAUDE_CODE_PKG,
                version=norm,
                status=ST.ENABLED.value,
                purpose="Claude Code CLI 主程序",
                source="Claude Code",
                ecosystem="npm",
                manager="npm",
                package_name=_CLAUDE_CODE_PKG,
                install_path=install_path,
                can_disable=False,
                can_uninstall=False,
                can_update=True,
            )
        ]

    def _skills(self, home: Optional[str], settings: dict) -> List[Asset]:
        out: List[Asset] = []
        enabled_ids = _enabled_plugin_ids(settings)
        seen_ids: Set[str] = set()

        if not home:
            out.sort(key=lambda a: a.name.lower())
            return out

        cache_dir = os.path.join(home, "plugins", "cache")
        if not os.path.isdir(cache_dir):
            out.sort(key=lambda a: a.name.lower())
            return out

        scan_roots: List[Tuple[str, Optional[str], bool]] = []
        for plugin_id in enabled_ids:
            root = _resolve_plugin_cache_dir(home, plugin_id)
            if root:
                scan_roots.append((root, plugin_id, True))

        for scan_root, plugin_id, is_enabled in scan_roots:
            for root, dirs, files in os.walk(scan_root):
                dirs[:] = [d for d in dirs if d not in SKIP_PLUGIN_DIRS]
                if "SKILL.md" not in files:
                    continue
                md = os.path.join(root, "SKILL.md")
                fm = parsers.parse_skill_frontmatter(md)
                if plugin_id:
                    rel = os.path.relpath(root, scan_root).replace(os.sep, "/")
                    plugin_label = plugin_id
                else:
                    rel = os.path.relpath(root, cache_dir).replace(os.sep, "/")
                    plugin_label = rel.split("/")[0] if rel else ""
                name = fm.get("name") or os.path.basename(root)
                slug = _slug(f"{plugin_label}-{rel}" if plugin_id else rel)
                asset_id = f"claude-skill-{slug}"
                if asset_id in seen_ids:
                    continue
                seen_ids.add(asset_id)
                active = is_enabled and (
                    not plugin_id
                    or _plugin_matches_path(plugin_id, rel, str(name))
                    or _plugin_matches_path(
                        plugin_id,
                        os.path.relpath(scan_root, cache_dir).replace(os.sep, "/"),
                        str(name),
                    )
                )
                perms = parsers.perms_from_skill_frontmatter(slug, str(name), fm)
                purpose = str(fm.get("description", "")) or "插件技能"
                if plugin_id:
                    purpose = f"{purpose}|plugin:{plugin_id}"
                out.append(
                    Asset(
                        id=asset_id,
                        agent_id="claude",
                        type=AT.SKILL.value,
                        name=str(name),
                        version=str(fm.get("version", "")) or None,
                        status=ST.ENABLED.value if active else ST.DISABLED.value,
                        purpose=purpose,
                        source="Claude Code",
                        skill_scope="global",
                        permissions=perms,
                        path=md,
                        can_disable=False,
                        can_uninstall=False,
                        can_update=False,
                    )
                )
        out.sort(key=lambda a: a.name.lower())
        return out

    def _marketplaces(self, home: Optional[str], settings: dict) -> List[Asset]:
        raw = settings.get("extraKnownMarketplaces")
        if not raw:
            return []
        entries: List[Tuple[str, dict]] = []
        if isinstance(raw, dict):
            for key, val in raw.items():
                entries.append((str(key), val if isinstance(val, dict) else {}))
        elif isinstance(raw, list):
            for idx, entry in enumerate(raw):
                if isinstance(entry, str):
                    entries.append((entry, {}))
                elif isinstance(entry, dict):
                    name = str(
                        entry.get("name") or entry.get("id") or entry.get("url") or f"marketplace-{idx}"
                    )
                    entries.append((name, entry))
        else:
            return []
        out: List[Asset] = []
        settings_path = self._settings_path(home) or claude_json_path()
        for name, entry in entries:
            slug = _slug(name)
            repo = ""
            if isinstance(entry.get("source"), dict):
                repo = str(entry["source"].get("repo") or "")
            purpose = "插件市场来源"
            if repo:
                purpose = f"{purpose}|repo:{repo}"
            out.append(
                Asset(
                    id=f"claude-marketplace-{slug}",
                    agent_id="claude",
                    type=AT.KNOWLEDGE.value,
                    name=name,
                    version=None,
                    status=ST.ENABLED.value,
                    purpose=purpose,
                    source="Claude Code",
                    permissions=[],
                    path=settings_path,
                    config_key=f"extraKnownMarketplaces.{name}",
                    can_disable=False,
                    can_uninstall=False,
                    can_update=False,
                )
            )
        return out

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        settings = getattr(self, "_settings", None) or {}
        out: List[Tuple[str, str]] = []
        seen: Set[str] = set()

        def add(path: str, source: str) -> None:
            if path and path not in seen and os.path.isfile(path):
                seen.add(path)
                out.append((path, source))

        settings_path = self._settings_path(home)
        if settings_path:
            add(settings_path, SRC.AGENT_CONFIG.value)
        if home:
            local_settings = os.path.join(home, "settings.local.json")
            add(local_settings, SRC.AGENT_CONFIG.value)

        cj = claude_json_path()
        if os.path.isfile(cj):
            try:
                if os.path.getsize(cj) <= CLAUDE_JSON_MAX_BYTES:
                    add(cj, SRC.AGENT_CONFIG.value)
            except OSError:
                pass

        if home:
            for plugin_id in _enabled_plugin_ids(settings):
                root = _resolve_plugin_cache_dir(home, str(plugin_id))
                if not root:
                    continue
                for walk_root, dirs, files in os.walk(root):
                    dirs[:] = [d for d in dirs if d not in SKIP_PLUGIN_DIRS]
                    if "SKILL.md" in files:
                        add(os.path.join(walk_root, "SKILL.md"), SRC.SKILL.value)
                hooks_path = _plugin_hooks_path(root)
                if hooks_path:
                    add(hooks_path, SRC.AGENT_CONFIG.value)
                manifest = _plugin_manifest(root)
                mcp_field = manifest.get("mcpServers")
                if isinstance(mcp_field, str):
                    add(os.path.join(root, mcp_field.lstrip("./")), SRC.MCP.value)
                add(os.path.join(root, ".mcp.json"), SRC.MCP.value)

            skills_dir = os.path.join(home, "skills")
            if os.path.isdir(skills_dir):
                for root, dirs, files in os.walk(skills_dir):
                    dirs[:] = [d for d in dirs if d not in SKIP_PLUGIN_DIRS]
                    if "SKILL.md" in files:
                        add(os.path.join(root, "SKILL.md"), SRC.SKILL.value)

        claude_json = getattr(self, "_claude_json", None) or parsers.read_json(claude_json_path()) or {}
        for project_path, _proj in _iter_projects(claude_json):
            for fname in _PROJECT_RULE_FILES:
                add(os.path.join(project_path, fname), SRC.AGENT_CONFIG.value)
            rules_dir = os.path.join(project_path, ".claude", "rules")
            if os.path.isdir(rules_dir):
                for root, _dirs, files in os.walk(rules_dir):
                    for fname in files:
                        if fname.endswith(".md"):
                            add(os.path.join(root, fname), SRC.AGENT_CONFIG.value)
            mcp_path = os.path.join(project_path, ".mcp.json")
            add(mcp_path, SRC.MCP.value)

        return out

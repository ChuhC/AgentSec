"""Hermes Adapter：解析真机 ~/.hermes 安装。

真实格式：
  config.yaml          model / mcp_servers / terminal / web / browser 等
  .update_check        {"ver": "0.16.0"}
  skills/**/SKILL.md   YAML frontmatter（name/version/description/...）
  hermes-agent/          npm workspace（package-lock 全树 + 各 workspace package.json + pyproject.toml）
"""

from __future__ import annotations

import json
import os
from typing import List, Optional, Tuple

from ..models import Agent, Asset, AssetStatus, AssetType, FindingSource, PermissionEntry, Severity
from . import parsers
from .base import AgentAdapter

ST = AssetStatus
AT = AssetType
SRC = FindingSource
S = Severity


class HermesAdapter(AgentAdapter):
    kind = "hermes"

    def detect(self) -> Optional[Agent]:
        home = self.resolve_home()
        if not home:
            return None
        cfg = parsers.read_yaml(os.path.join(home, "config.yaml")) or {}
        if not cfg and not os.path.isdir(os.path.join(home, "skills")):
            return None
        self._home = home
        self._cfg = cfg
        return Agent(
            id="hermes", name="Hermes Agent", kind="hermes",
            version=self._version(home),
            listen_ports=parsers.collect_listen_ports(cfg, home),
            enabled=True,
            description=self._description(cfg),
            permissions=self._agent_perms(cfg),
        )

    def _version(self, home: str) -> str:
        data = parsers.read_json(os.path.join(home, ".update_check"))
        if data and data.get("ver"):
            return "v" + str(data["ver"])
        return ""

    def _description(self, cfg: dict) -> str:
        model = (cfg.get("model") or {}).get("default", "")
        return f"通用智能体（模型：{model}）" if model else "通用智能体"

    def _agent_perms(self, cfg: dict) -> List[PermissionEntry]:
        out = []
        if (cfg.get("terminal") or {}).get("backend") == "local":
            out.append(parsers.perm("a-h-shell", "shell", SRC.AGENT_CONFIG, "Agent 默认"))
        if cfg.get("web") or cfg.get("browser"):
            out.append(parsers.perm("a-h-net", "network", SRC.AGENT_CONFIG, "Agent 默认"))
        if cfg.get("file_read_max_chars"):
            out.append(parsers.perm("a-h-file", "file", SRC.AGENT_CONFIG, "Agent 默认"))
        return out

    def discover_assets(self, agent: Agent) -> List[Asset]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        cfg = getattr(self, "_cfg", None) or parsers.read_yaml(os.path.join(home, "config.yaml")) or {}
        return (
            self._mcp(home, cfg)
            + self._skills(home)
            + self._deps(home)
            + parsers.discover_channels(
                "hermes", "Hermes", cfg, os.path.join(home, "config.yaml"), roots=("platforms",)
            )
        )

    def _mcp(self, home: str, cfg: dict) -> List[Asset]:
        out = []
        cfg_path = os.path.join(home, "config.yaml")
        for name, srv in (cfg.get("mcp_servers") or {}).items():
            if not isinstance(srv, dict):
                continue
            perms = parsers.perms_from_mcp_server(name, srv)
            purpose = parsers.describe_mcp_purpose(name, srv)
            disabled = srv.get("enabled") is False
            npm_pkg = parsers.parse_mcp_npm_package(srv)
            version = str(srv.get("version", "")) or None
            install_path = None
            manager = None
            package_name = None
            if npm_pkg:
                package_name = npm_pkg
                manager = "npm"
                env = srv.get("env") or {}
                node_path = str(env.get("NODE_PATH", ""))
                search = node_path if node_path else home
                pkg_json = os.path.join(search, "package.json")
                pkg_data = parsers.read_json(pkg_json) or {}
                version = str(pkg_data.get("version", "")) or None
                version = parsers.installed_npm_version(npm_pkg, search) or version
                install_path = search or None
            else:
                env = srv.get("env") or {}
                node_path = str(env.get("NODE_PATH", ""))
                if node_path and os.path.isdir(node_path):
                    pkg_data = parsers.read_json(os.path.join(node_path, "package.json")) or {}
                    if pkg_data.get("name"):
                        package_name = str(pkg_data["name"])
                        manager = "npm"
                        install_path = node_path
                        version = str(pkg_data.get("version", "")) or version
                for arg in srv.get("args") or []:
                    if str(arg).endswith((".mjs", ".js")):
                        script = str(arg)
                        version = parsers.mcp_local_version(script) or version
                        script_dir = os.path.dirname(script)
                        pkg_data = parsers.read_json(os.path.join(script_dir, "package.json")) or {}
                        if pkg_data.get("name"):
                            package_name = str(pkg_data["name"])
                            install_path = script_dir
                        break
            out.append(Asset(
                id=f"hermes-mcp-{name}", agent_id="hermes", type=AT.MCP.value,
                name=name, version=version,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=purpose, source="Hermes", permissions=perms,
                path=cfg_path, config_key=name,
                manager=manager,
                install_path=install_path or (str((srv.get("env") or {}).get("NODE_PATH", "")) or None),
                package_name=package_name,
                can_disable=True, can_uninstall=False,
            ))
        return out

    def _skills(self, home: str) -> List[Asset]:
        skills_dir = os.path.join(home, "skills")
        if not os.path.isdir(skills_dir):
            return []
        out = []
        for root, _dirs, files in os.walk(skills_dir):
            disabled = "SKILL.md.disabled" in files
            if "SKILL.md" not in files and not disabled:
                continue
            fname = "SKILL.md.disabled" if disabled else "SKILL.md"
            md = os.path.join(root, fname)
            fm = parsers.parse_skill_frontmatter(md)
            rel = os.path.relpath(root, skills_dir).replace(os.sep, "/")
            name = fm.get("name") or os.path.basename(root)
            perms = parsers.perms_from_skill_frontmatter(rel.replace("/", "-"), name, fm)
            out.append(Asset(
                id=f"hermes-skill-{rel}", agent_id="hermes", type=AT.SKILL.value,
                name=name, version=str(fm.get("version", "")) or None,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=str(fm.get("description", "")) or "本机技能", source="Hermes",
                skill_scope="user",
                permissions=perms, path=md,
                can_disable=False, can_uninstall=False,
            ))
        out.sort(key=lambda a: a.name.lower())
        return out

    def _deps(self, home: str) -> List[Asset]:
        agent_dir = os.path.join(home, "hermes-agent")
        deps = parsers.deps_from_npm_workspace(agent_dir, "hermes")
        # 真实 npm 管理上下文（仅用于版本/CVE 定位，不提供更新/卸载操作）
        for d in deps:
            if d.ecosystem == "npm":
                d.manager = "npm"
                d.install_path = agent_dir
                d.package_name = d.name
            elif d.ecosystem == "PyPI":
                d.manager = "pip"
                d.install_path = agent_dir
                d.package_name = d.name
            d.can_disable = False
        return deps

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        cfg = getattr(self, "_cfg", None) or parsers.read_yaml(os.path.join(home, "config.yaml")) or {}
        cfg_path = os.path.join(home, "config.yaml")
        out: List[Tuple[str, str]] = []
        seen: set[str] = set()

        def add(path: str, source: str) -> None:
            if path and path not in seen and os.path.isfile(path):
                seen.add(path)
                out.append((path, source))

        if os.path.isfile(cfg_path):
            add(cfg_path, SRC.AGENT_CONFIG.value)
        for asset in self._mcp(home, cfg):
            if asset.path and asset.path != cfg_path:
                add(asset.path, SRC.MCP.value)
        for mcp_path in parsers.collect_atr_mcp_config_paths(home, cfg, cfg_path):
            add(mcp_path, SRC.MCP.value)
        skills_dir = os.path.join(home, "skills")
        if os.path.isdir(skills_dir):
            for root, _dirs, files in os.walk(skills_dir):
                if "SKILL.md" in files:
                    add(os.path.join(root, "SKILL.md"), SRC.SKILL.value)
        return out


def _looks_secret(key: str) -> bool:
    k = key.lower()
    return any(t in k for t in ("key", "token", "secret", "password", "api"))

"""OpenClaw Adapter：解析真机 OpenClaw 安装。

真实格式：~/.openclaw/openclaw.json 或 ~/.openclaw/settings.json（根目录主配置）。
~/.openclaw/claw3d/ 为 Hermes Agent 桌面 3D 场景资源，不是独立 OpenClaw 产品。
基线补充（openclaw security audit --json）由 ExposureDetector 处理（需 openclaw CLI）。
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..models import Agent, Asset, AssetStatus, AssetType, FindingSource
from . import parsers
from .base import AgentAdapter

ST = AssetStatus
AT = AssetType
SRC = FindingSource

# 真 OpenClaw 主配置；不含 claw3d/（Hermes 桌面 UI 场景）
_REAL_CONFIG_NAMES = ("openclaw.json", "settings.json")


class OpenClawAdapter(AgentAdapter):
    kind = "openclaw"

    def _real_config_path(self, home: str) -> Optional[str]:
        for name in _REAL_CONFIG_NAMES:
            p = os.path.join(home, name)
            if os.path.isfile(p):
                return p
        return None

    def detect(self) -> Optional[Agent]:
        home = self.resolve_home()
        if not home:
            return None
        sp = self._real_config_path(home)
        if not sp:
            return None
        self._home = home
        self._settings_path_cache = sp
        data = parsers.read_json(sp) or {}
        profiles = list(((data.get("gateway") or {}).get("profiles") or {}).keys())
        desc = "OpenClaw Agent"
        if profiles:
            desc += f"（gateway profiles：{', '.join(profiles)}）"
        gw = data.get("gateway") or {}
        ports: List[str] = []
        if gw.get("port"):
            ports.append(str(gw["port"]))
        for plat in (data.get("platforms") or {}).values():
            if isinstance(plat, dict):
                extra = plat.get("extra") or {}
                if extra.get("port"):
                    ports.append(str(extra["port"]))
        ver_raw = data.get("version") or ""
        return Agent(
            id="openclaw", name="OpenClaw", kind="openclaw",
            version="v" + str(ver_raw) if ver_raw else "",
            latest_version=(
                "v" + str(data["latest_version"])
                if data.get("latest_version")
                else None
            ),
            listen_ports=ports,
            enabled=True, description=desc,
            permissions=[parsers.perm("a-o-net", "network", SRC.AGENT_CONFIG, "Agent 默认")],
        )

    def discover_assets(self, agent: Agent) -> List[Asset]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        sp = getattr(self, "_settings_path_cache", None) or self._real_config_path(home)
        data = parsers.read_json(sp) or {} if sp else {}
        return self._mcp(home, data, sp) + self._skills(home) + self._deps(home)

    def _mcp(self, home: str, data: dict, cfg_path: Optional[str]) -> List[Asset]:
        out: List[Asset] = []
        cfg_path = cfg_path or os.path.join(home, "openclaw.json")
        for name, srv in (data.get("mcp_servers") or {}).items():
            if not isinstance(srv, dict):
                continue
            cmd = " ".join([str(srv.get("command", ""))] + [str(a) for a in srv.get("args", [])]).strip()
            perms = parsers.perms_from_mcp_server(name, srv)
            disabled = srv.get("enabled") is False
            npm_pkg = parsers.parse_mcp_npm_package(srv)
            version = str(srv.get("version", "")) or None
            if npm_pkg:
                version = parsers.installed_npm_version(npm_pkg, home) or version
            out.append(Asset(
                id=f"openclaw-mcp-{name}",
                agent_id="openclaw",
                type=AT.MCP.value,
                name=name,
                version=version,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=f"MCP 服务：{cmd}" if cmd else "MCP 服务",
                source="OpenClaw",
                permissions=perms,
                path=cfg_path,
                config_key=name,
                manager="npm" if npm_pkg else None,
                package_name=npm_pkg,
                can_disable=True,
                can_uninstall=False,
                can_update=bool(npm_pkg) and not disabled,
            ))
        return out

    def _skills(self, home: str) -> List[Asset]:
        skills_dir = os.path.join(home, "skills")
        if not os.path.isdir(skills_dir):
            return []
        out: List[Asset] = []
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
                id=f"openclaw-skill-{rel}",
                agent_id="openclaw",
                type=AT.SKILL.value,
                name=name,
                version=str(fm.get("version", "")) or None,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=str(fm.get("description", "")) or "本机技能",
                source="OpenClaw",
                permissions=perms,
                path=md,
                can_disable=True,
                can_uninstall=False,
            ))
        out.sort(key=lambda a: a.name.lower())
        return out

    def _deps(self, home: str) -> List[Asset]:
        out: List[Asset] = []
        for name in ("requirements.txt", "pyproject.toml"):
            path = os.path.join(home, name)
            if name == "requirements.txt":
                out.extend(parsers.deps_from_requirements(path, "openclaw"))
            elif os.path.isfile(path):
                out.extend(parsers.deps_from_pyproject(path, "openclaw"))
        for d in out:
            if d.ecosystem == "PyPI":
                d.manager = "pip"
                d.install_path = home
                d.package_name = d.name
                d.can_update = True
                d.can_uninstall = True
            d.can_disable = False
        return out

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        sp = getattr(self, "_settings_path_cache", None) or self._real_config_path(home)
        return [(sp, SRC.AGENT_CONFIG.value)] if sp else []

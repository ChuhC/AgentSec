"""OpenClaw Adapter：解析真机 OpenClaw 安装。

真实格式：~/.openclaw/openclaw.json 或 ~/.openclaw/settings.json（根目录主配置）。
~/.openclaw/claw3d/ 为 Hermes Agent 桌面 3D 场景资源，不是独立 OpenClaw 产品。
基线补充（openclaw security audit --json）由 ExposureDetector 处理（需 openclaw CLI）。
"""

from __future__ import annotations

import json
import os
import subprocess
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
        ver_raw = parsers.resolve_openclaw_installed_version(data.get("version"))
        return Agent(
            id="openclaw", name="OpenClaw", kind="openclaw",
            version=ver_raw,
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
        cfg_path = sp or os.path.join(home, "openclaw.json")
        return (
            self._mcp(home, data, sp)
            + self._discover_skills(home, data)
            + self._deps(home, data)
            + parsers.discover_channels(
                "openclaw",
                "OpenClaw",
                data,
                cfg_path,
                roots=("channels", "platforms"),
            )
        )

    def _discover_skills(self, home: str, data: dict) -> List[Asset]:
        roots = parsers.openclaw_skill_roots(home, data)
        roots = self._extend_skill_roots_from_cli(roots)
        assets = parsers.discover_skills_in_roots("openclaw", "OpenClaw", roots)
        return self._merge_skills_cli(assets)

    def _extend_skill_roots_from_cli(
        self, roots: List[Tuple[str, str]]
    ) -> List[Tuple[str, str]]:
        """用 openclaw skills list --json 补齐 workspace / managed 根目录。"""
        cli = parsers.resolve_openclaw_cli()
        if not cli:
            return roots
        try:
            proc = subprocess.run(
                [cli, "skills", "list", "--json"],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except (OSError, subprocess.TimeoutExpired):
            return roots
        if proc.returncode != 0 or not proc.stdout.strip():
            return roots
        try:
            payload = json.loads(proc.stdout)
        except ValueError:
            return roots

        seen = {os.path.realpath(p) for p, _ in roots if os.path.isdir(p)}
        extra: List[Tuple[str, str]] = []

        def add(path: Optional[str], label: str) -> None:
            if not path:
                return
            real = os.path.realpath(os.path.expanduser(path))
            if real in seen or not os.path.isdir(real):
                return
            seen.add(real)
            extra.append((real, label))

        ws = payload.get("workspaceDir")
        if ws:
            add(os.path.join(str(ws), "skills"), "workspace")
            add(os.path.join(str(ws), ".agents", "skills"), "project-agent")
        managed = payload.get("managedSkillsDir")
        if managed:
            add(str(managed), "managed")
        return extra + roots

    def _merge_skills_cli(self, assets: List[Asset]) -> List[Asset]:
        """用 openclaw skills list --json 同步 disabled / 来源等运行时状态。"""
        cli = parsers.resolve_openclaw_cli()
        if not cli:
            return assets
        try:
            proc = subprocess.run(
                [cli, "skills", "list", "--json"],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except (OSError, subprocess.TimeoutExpired):
            return assets
        if proc.returncode != 0 or not proc.stdout.strip():
            return assets
        try:
            payload = json.loads(proc.stdout)
        except ValueError:
            return assets
        meta_by_name = {
            str(s.get("name")): s
            for s in (payload.get("skills") or [])
            if s.get("name")
        }
        for asset in assets:
            meta = meta_by_name.get(asset.name)
            if not meta:
                continue
            if meta.get("disabled"):
                asset.status = ST.DISABLED.value
            src = str(meta.get("source") or "").strip()
            if src and src not in (asset.purpose or ""):
                asset.purpose = f"{(asset.purpose or '本机技能').split('（来源：')[0]}（来源：{src}）"
            if meta.get("eligible") is False and asset.status != ST.DISABLED.value:
                missing = meta.get("missing") or {}
                hints: List[str] = []
                for key in ("bins", "anyBins", "env", "config"):
                    vals = missing.get(key) or []
                    if vals:
                        hints.append(f"{key}: {', '.join(str(v) for v in vals[:3])}")
                if hints:
                    asset.purpose = f"{asset.purpose}（待配置：{'; '.join(hints)}）"
        return assets

    def _mcp(self, home: str, data: dict, cfg_path: Optional[str]) -> List[Asset]:
        out: List[Asset] = []
        cfg_path = cfg_path or os.path.join(home, "openclaw.json")
        for name, srv in (data.get("mcp_servers") or {}).items():
            if not isinstance(srv, dict):
                continue
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
                purpose=parsers.describe_mcp_purpose(name, srv),
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

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        sp = getattr(self, "_settings_path_cache", None) or self._real_config_path(home)
        out: List[Tuple[str, str]] = []
        if sp:
            out.append((sp, SRC.AGENT_CONFIG.value))
        data = parsers.read_json(sp) or {} if sp else {}
        for skill in self._discover_skills(home, data):
            if skill.path and os.path.isfile(skill.path):
                out.append((skill.path, SRC.SKILL.value))
        return out

    def _deps(self, home: str, _data: dict) -> List[Asset]:
        return parsers.discover_openclaw_dependencies(home)

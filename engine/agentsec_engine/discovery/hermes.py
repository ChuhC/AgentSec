"""Hermes Adapter：解析真机 ~/.hermes 安装。

真实格式：
  config.yaml          model / mcp_servers / terminal / web / browser 等
  .update_check        {"ver": "0.16.0"}
  skills/**/SKILL.md   YAML frontmatter（name/version/description/...）
  hermes-agent/package.json   npm 依赖
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
        return self._mcp(home, cfg) + self._skills(home) + self._deps(home)

    def _mcp(self, home: str, cfg: dict) -> List[Asset]:
        out = []
        cfg_path = os.path.join(home, "config.yaml")
        for name, srv in (cfg.get("mcp_servers") or {}).items():
            if not isinstance(srv, dict):
                continue
            cmd = " ".join([str(srv.get("command", ""))] + [str(a) for a in srv.get("args", [])]).strip()
            perms = [parsers.perm(f"hermes-{name}-net", "network", SRC.MCP, f"{name} MCP")]
            # 凭证：仅记录键名引用，绝不存值（NF-S2）
            env_keys = [k for k in (srv.get("env") or {}).keys() if _looks_secret(k)]
            purpose = f"MCP 服务：{cmd}" if cmd else "MCP 服务"
            if env_keys:
                purpose += f"（凭证引用：{', '.join(env_keys)}）"
            disabled = srv.get("enabled") is False
            out.append(Asset(
                id=f"hermes-mcp-{name}", agent_id="hermes", type=AT.MCP.value,
                name=name, version=str(srv.get("version", "")) or None,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=purpose, source="Hermes", permissions=perms,
                path=cfg_path, config_key=name,
                can_disable=True, can_uninstall=False,  # 卸载=改主配置，灰显需手动
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
            perms = []
            pre = (fm.get("prerequisites") or {}) if isinstance(fm.get("prerequisites"), dict) else {}
            if pre.get("commands"):
                perms.append(parsers.perm(f"hermes-sk-{rel}-exec", "exec", SRC.SKILL, name, S.MEDIUM))
            out.append(Asset(
                id=f"hermes-skill-{rel}", agent_id="hermes", type=AT.SKILL.value,
                name=name, version=str(fm.get("version", "")) or None,
                status=ST.DISABLED.value if disabled else ST.ENABLED.value,
                purpose=str(fm.get("description", "")) or "本机技能", source="Hermes",
                permissions=perms, path=md,
                can_disable=True, can_uninstall=False,  # 删目录危险，灰显需手动
            ))
        out.sort(key=lambda a: a.name.lower())
        return out

    def _deps(self, home: str) -> List[Asset]:
        agent_dir = os.path.join(home, "hermes-agent")
        deps = parsers.deps_from_package_json(
            os.path.join(agent_dir, "package.json"), "hermes"
        )
        # 真实 npm 管理上下文：更新/卸载经包管理器（强确认在 UI 侧）
        for d in deps:
            d.manager = "npm"
            d.install_path = agent_dir
            d.package_name = d.name
            d.can_update = True
            d.can_uninstall = True
            d.can_disable = False
        return deps

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        out: List[Tuple[str, str]] = []
        cfg_path = os.path.join(home, "config.yaml")
        if os.path.isfile(cfg_path):
            out.append((cfg_path, SRC.AGENT_CONFIG.value))
        skills_dir = os.path.join(home, "skills")
        if os.path.isdir(skills_dir):
            for root, _dirs, files in os.walk(skills_dir):
                if "SKILL.md" in files:
                    out.append((os.path.join(root, "SKILL.md"), SRC.SKILL.value))
        return out


def _looks_secret(key: str) -> bool:
    k = key.lower()
    return any(t in k for t in ("key", "token", "secret", "password", "api"))

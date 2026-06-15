"""OpenClaw Adapter：解析真机 OpenClaw 安装。

真实格式：~/.openclaw/openclaw.json 或 ~/.openclaw/settings.json（根目录主配置）。
~/.openclaw/claw3d/ 为 Hermes Agent 桌面 3D 场景资源，不是独立 OpenClaw 产品。
基线补充（openclaw security audit --json）由 ExposureDetector 处理（需 openclaw CLI）。
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..models import Agent, Asset, FindingSource
from . import parsers
from .base import AgentAdapter

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
        return Agent(
            id="openclaw", name="OpenClaw", kind="openclaw",
            version="v" + str(data.get("version", "")) if data.get("version") else "",
            enabled=True, description=desc,
            permissions=[parsers.perm("a-o-net", "network", SRC.AGENT_CONFIG, "Agent 默认")],
        )

    def discover_assets(self, agent: Agent) -> List[Asset]:
        return []

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        home = getattr(self, "_home", None) or self.resolve_home()
        if not home:
            return []
        sp = getattr(self, "_settings_path_cache", None) or self._real_config_path(home)
        return [(sp, SRC.AGENT_CONFIG.value)] if sp else []

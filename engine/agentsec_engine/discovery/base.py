"""Adapter 统一端口（architecture.md 五·4）。

每个 Agent 产品实现一个 Adapter：定位安装、解析真机配置、枚举资产。
真机解析（real-only）：各 Adapter 解析本机真实安装；无安装则该 Agent 不存在。

家目录解析顺序（detect 时）：
  1. config.json agents.<kind>_home（或环境变量 AGENTSEC_<KIND>_HOME 覆盖）
  2. 自定义扫描根 scope_path 下的 .<kind> 目录
  3. 用户主目录 ~/.<kind>
都不存在 → 该 Agent not_found（不展示 demo 数据）。
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..config import get_agent_home
from ..models import Agent, Asset


class AgentAdapter:
    kind = "base"

    def __init__(self, scope_path: Optional[str] = None):
        # scope_path: None=本机全部；否则为自定义扫描根
        self.scope_path = scope_path

    def resolve_home(self) -> Optional[str]:
        """按优先级定位该 Agent 的配置家目录；都不存在返回 None。"""
        candidates: List[str] = []
        env = get_agent_home(self.kind)
        if env:
            candidates.append(env)
        if self.scope_path:
            candidates.append(os.path.join(self.scope_path, f".{self.kind}"))
        candidates.append(os.path.join(os.path.expanduser("~"), f".{self.kind}"))
        for c in candidates:
            if c and os.path.isdir(c):
                return c
        return None

    def detect(self) -> Optional[Agent]:
        """探测本机是否存在该 Agent；不存在返回 None。"""
        raise NotImplementedError

    def discover_assets(self, agent: Agent) -> List[Asset]:
        """枚举该 Agent 的 MCP / Skill / 知识库 / 依赖。"""
        raise NotImplementedError

    def atr_targets(self, agent: Agent) -> List[Tuple[str, str]]:
        """返回应喂给 ATR 的可扫文件：[(绝对路径, source), ...]。

        source ∈ {mcp, skill, agent_config}（对齐 FindingSource）。
        """
        return []

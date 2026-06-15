"""Adapter 注册与发现入口。"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..models import Agent, Asset
from .base import AgentAdapter
from .hermes import HermesAdapter
from .openclaw import OpenClawAdapter

ADAPTERS = [HermesAdapter, OpenClawAdapter]


def discover_all(
    scope_path: Optional[str] = None,
) -> Tuple[List[Agent], List[Asset], List[Tuple[str, str, List[str]]], dict]:
    """运行所有 Adapter，返回 (agents, assets, atr_targets, adapter_status)。

    atr_targets: [(path, source, [agent_id]), ...]，供 ExposureDetector 喂 ATR。
    单个 Adapter 失败不阻塞其他（architecture.md 五·1）。
    """
    agents: List[Agent] = []
    assets: List[Asset] = []
    targets: List[Tuple[str, str, List[str]]] = []
    status: dict = {}
    for cls in ADAPTERS:
        adapter: AgentAdapter = cls(scope_path=scope_path)
        try:
            agent = adapter.detect()
            if agent is None:
                status[cls.kind] = "not_found"
                continue
            agents.append(agent)
            assets.extend(adapter.discover_assets(agent))
            for path, source in adapter.atr_targets(agent):
                targets.append((path, source, [agent.id]))
            status[cls.kind] = "ok"
        except Exception as exc:  # noqa: BLE001 - 隔离单 Adapter 失败
            status[cls.kind] = "error: " + str(exc)
    return agents, assets, targets, status

"""Adapter 注册与发现入口。"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from ..enrichment import enrich_discovery
from ..models import Agent, Asset
from .base import AgentAdapter
from .claude import ClaudeAdapter
from .hermes import HermesAdapter
from .openclaw import OpenClawAdapter

ADAPTERS = [HermesAdapter, OpenClawAdapter, ClaudeAdapter]

_ADAPTER_BY_KIND = {cls.kind: cls for cls in ADAPTERS}


def _adapter_homes(scope_path: Optional[str]) -> Dict[str, str]:
    homes: Dict[str, str] = {}
    for cls in ADAPTERS:
        adapter: AgentAdapter = cls(scope_path=scope_path)
        home = adapter.resolve_home()
        if home:
            homes[cls.kind] = home
    return homes


def discover_agent(
    agent_id: str,
    scope_path: Optional[str] = None,
    online: bool = True,
    force_update_check: bool = False,
) -> tuple:
    """重新发现单个 Agent，返回 (agent, assets, status)。"""
    cls = _ADAPTER_BY_KIND.get(agent_id)
    if cls is None:
        return None, [], "unknown_agent"
    adapter: AgentAdapter = cls(scope_path=scope_path)
    try:
        agent = adapter.detect()
        if agent is None:
            return None, [], "not_found"
        assets = adapter.discover_assets(agent)
        homes = {agent.id: adapter.resolve_home()} if adapter.resolve_home() else {}
        enrich_discovery([agent], assets, homes=homes, online=online, force_update_check=force_update_check)
        return agent, assets, "ok"
    except Exception as exc:  # noqa: BLE001
        return None, [], "error: " + str(exc)


def discover_all(
    scope_path: Optional[str] = None,
    online: bool = True,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Tuple[List[Agent], List[Asset], List[Tuple[str, str, List[str]]], dict]:
    """运行所有 Adapter，返回 (agents, assets, atr_targets, adapter_status)。

    atr_targets: [(path, source, [agent_id]), ...]，供 ExposureDetector 喂 ATR。
    单个 Adapter 失败不阻塞其他（architecture.md 五·1）。
    """
    agents: List[Agent] = []
    assets: List[Asset] = []
    targets: List[Tuple[str, str, List[str]]] = []
    status: dict = {}
    homes = _adapter_homes(scope_path)
    for cls in ADAPTERS:
        if should_cancel and should_cancel():
            break
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
    if not (should_cancel and should_cancel()):
        enrich_discovery(agents, assets, homes=homes, online=online)
    return agents, assets, targets, status

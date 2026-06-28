"""发现后 enrichment：补齐 UI 所需的版本、可更新状态与 Agent 元数据。"""

from __future__ import annotations

import re
from typing import List, Optional

from .models import Agent, Asset, AssetStatus, AssetType
from .registry_client import fetch_npm_latest, fetch_pypi_latest
from .update_check import (
    apply_update_info,
    check_claude_update,
    check_hermes_update,
    check_openclaw_update,
)

ST = AssetStatus
AT = AssetType

_VER_TOKEN = re.compile(r"[0-9][\w.\-]*")


def normalize_version(ver: Optional[str]) -> str:
    if not ver:
        return ""
    s = str(ver).strip().lstrip("vV")
    m = _VER_TOKEN.search(s)
    return m.group(0) if m else s


def version_tuple(ver: str) -> tuple:
    parts = []
    for p in normalize_version(ver).replace("-", ".").split("."):
        num = re.match(r"(\d+)", p)
        parts.append(int(num.group(1)) if num else 0)
    return tuple(parts)


def is_newer(latest: str, current: str) -> bool:
    la, cu = normalize_version(latest), normalize_version(current)
    if not la or not cu:
        return bool(la and la != cu)
    try:
        return version_tuple(la) > version_tuple(cu)
    except (ValueError, TypeError):
        return la != cu


def _with_v(ver: str) -> str:
    s = normalize_version(ver)
    return f"v{s}" if s else ""


def enrich_agent(
    agent: Agent,
    home: Optional[str] = None,
    online: bool = True,
    *,
    force_update_check: bool = False,
) -> None:
    """补齐 Agent 版本与更新状态（官方 CLI + registry）。"""
    if agent.kind == "hermes" and home:
        info = check_hermes_update(
            home,
            online=online,
            force=force_update_check,
            current_version=agent.version,
        )
        apply_update_info(agent, info)
    elif agent.kind == "openclaw" and home:
        if not agent.version:
            from .discovery import parsers

            agent.version = parsers.resolve_openclaw_installed_version()
        info = check_openclaw_update(home, online=online, current_version=agent.version)
        apply_update_info(agent, info)
    elif agent.kind == "claude":
        from .discovery.claude import resolve_claude_installed_version

        resolved = resolve_claude_installed_version()
        if resolved:
            agent.version = resolved
        info = check_claude_update(online=online, current_version=agent.version)
        apply_update_info(agent, info)
    elif agent.latest_version is None and agent.version:
        agent.latest_version = agent.version


def _apply_version_fields(
    asset: Asset,
    latest: Optional[str],
    *,
    can_update: bool = True,
) -> None:
    if asset.status == ST.DISABLED.value:
        return
    cur = normalize_version(asset.version)
    lat = normalize_version(latest) if latest else ""
    if lat and cur and is_newer(lat, cur):
        asset.latest_version = lat
        asset.status = ST.UPDATABLE.value
        asset.can_update = can_update
    elif lat and not cur:
        asset.version = lat
        asset.latest_version = lat
        asset.status = ST.ENABLED.value
    elif lat:
        asset.latest_version = lat


def enrich_assets(
    assets: List[Asset],
    online: bool = True,
    *,
    check_dep_versions: bool = False,
) -> None:
    for asset in assets:
        if asset.type == AT.DEPENDENCY.value:
            if check_dep_versions:
                _enrich_dependency(asset, online)
        elif asset.type == AT.MCP.value:
            _enrich_mcp(asset, online)
        elif asset.type in (AT.SKILL.value, AT.HOOK.value, AT.KNOWLEDGE.value):
            _enrich_static_asset(asset)


def _enrich_dependency(asset: Asset, online: bool) -> None:
    if not online or not asset.ecosystem:
        return
    eco = asset.ecosystem.lower()
    pkg = asset.package_name or asset.name
    latest = None
    if eco == "npm":
        latest = fetch_npm_latest(pkg)
    elif eco in ("pypi", "pip"):
        latest = fetch_pypi_latest(pkg)
    if latest and asset.manager:
        asset.can_update = True
        asset.can_uninstall = True
    _apply_version_fields(asset, latest, can_update=bool(asset.manager))


def _enrich_mcp(asset: Asset, online: bool) -> None:
    if not online:
        return
    pkg = asset.package_name
    if not pkg:
        return
    latest = fetch_npm_latest(pkg) if asset.manager == "npm" else None
    if latest:
        _apply_version_fields(asset, latest, can_update=bool(asset.can_update))


def _enrich_static_asset(asset: Asset) -> None:
    """Skill / 知识库：frontmatter 或发现阶段已写入 latest_version 时标记可更新。"""
    if asset.status == ST.DISABLED.value:
        return
    if asset.latest_version and is_newer(asset.latest_version, asset.version or ""):
        asset.status = ST.UPDATABLE.value
        asset.can_update = True


def enrich_discovery(
    agents: List[Agent],
    assets: List[Asset],
    homes: Optional[dict] = None,
    online: bool = True,
    *,
    check_dep_versions: bool = False,
    force_update_check: bool = False,
) -> None:
    """发现完成后统一 enrichment。"""
    homes = homes or {}
    for agent in agents:
        enrich_agent(
            agent,
            homes.get(agent.id),
            online=online,
            force_update_check=force_update_check,
        )
    enrich_assets(assets, online=online, check_dep_versions=check_dep_versions)

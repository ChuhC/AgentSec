"""Agent 级写操作：执行 Hermes / OpenClaw 官方更新并刷新快照。"""

from __future__ import annotations

from dataclasses import fields
from typing import Dict, List, Optional, Tuple

from .asset_manager import AssetOperationError
from .discovery.registry import _adapter_homes, discover_agent
from .models import Asset, AssetType, CVEStatus
from .store import SnapshotStore
from .update_check import run_hermes_update, run_openclaw_update


def scan_replacement_cves(
    snapshot: dict,
    agent_id: str,
    replacement_assets: List[Asset],
    online: bool,
) -> Tuple[list, str, dict]:
    """按刷新后的全量依赖重算 CVE，保证 Finding 与 meta 来自同一批数据。"""
    from .detectors.cve import CVEDetector, RemoteOSVProvider

    asset_fields = {item.name for item in fields(Asset)}
    retained = [
        item for item in snapshot.get("assets", [])
        if item.get("agent_id") != agent_id
    ]
    merged = retained + [item.to_dict() for item in replacement_assets]
    dependencies: List[Asset] = []
    invalid_dependencies = 0
    for item in merged:
        if item.get("type") != AssetType.DEPENDENCY.value:
            continue
        values = {key: value for key, value in item.items() if key in asset_fields}
        try:
            dependencies.append(Asset(**values))
        except TypeError:
            # 旧快照字段不完整时跳过该依赖，并由 diagnostics 体现未查询。
            invalid_dependencies += 1
            continue

    detector = CVEDetector(RemoteOSVProvider(online=online))
    findings, status = detector.scan(dependencies)
    diagnostics = dict(detector.last_diagnostics)
    diagnostics["dependency_count"] = len(dependencies)
    diagnostics["invalid_dependencies"] = invalid_dependencies
    diagnostics["skipped"] = int(diagnostics.get("skipped") or 0) + invalid_dependencies
    if invalid_dependencies and status == CVEStatus.OK.value:
        status = CVEStatus.PARTIAL.value
    return [finding.to_dict() for finding in findings], status, diagnostics


class AgentManager:
    def __init__(self, store: SnapshotStore):
        self.store = store

    def update(self, agent_id: str, scope_path: Optional[str] = None) -> Dict:
        snap = self.store.load()
        if not snap:
            raise AssetOperationError("无可用快照，请先完成一次全机扫描")
        agent = next((a for a in snap.get("agents", []) if a.get("id") == agent_id), None)
        if not agent:
            raise AssetOperationError("未找到 Agent：" + str(agent_id))
        if not agent.get("update_available"):
            raise AssetOperationError("当前 Agent 已是最新版本")
        if not agent.get("can_update"):
            cmd = agent.get("update_command") or ""
            raise AssetOperationError(
                "此安装方式不支持在 agentSec 内一键更新。"
                + (f" 请在终端执行：{cmd}" if cmd else "")
            )

        homes = _adapter_homes(scope_path)
        home = homes.get(agent_id)
        kind = agent.get("kind", agent_id)
        if kind == "hermes":
            if not home:
                raise AssetOperationError("未找到 Hermes 安装目录")
            run_hermes_update(home)
        elif kind == "openclaw":
            run_openclaw_update()
        else:
            raise AssetOperationError("不支持的 Agent 类型：" + str(kind))

        refreshed, assets, status = discover_agent(
            agent_id,
            scope_path=scope_path,
            online=True,
            force_update_check=True,
        )
        if status != "ok" or refreshed is None:
            raise AssetOperationError("更新后刷新 Agent 失败：" + str(status))

        cve_payload, cve_status, cve_diagnostics = scan_replacement_cves(
            snap, agent_id, assets, online=True
        )

        patched = self.store.patch_agent_discovery(
            agent_id,
            refreshed.to_dict(),
            [a.to_dict() for a in assets],
            cve_findings=cve_payload,
            replace_all_cve_findings=True,
            cve_status=cve_status,
            cve_diagnostics=cve_diagnostics,
        )
        if patched is None:
            raise AssetOperationError("更新成功但写入快照失败")
        return patched

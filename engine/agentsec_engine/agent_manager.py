"""Agent 级写操作：执行 Hermes / OpenClaw 官方更新并刷新快照。"""

from __future__ import annotations

from typing import Dict, Optional

from .asset_manager import AssetOperationError
from .discovery.registry import _adapter_homes, discover_agent
from .store import SnapshotStore
from .update_check import run_hermes_update, run_openclaw_update


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

        from .models import AssetType
        from .detectors.cve import CVEDetector, RemoteOSVProvider

        cve_payload = None
        deps = [a for a in assets if a.type == AssetType.DEPENDENCY.value]
        if deps:
            detector = CVEDetector()
            detector.provider = RemoteOSVProvider(online=True)
            findings, _ = detector.scan(deps)
            cve_payload = [f.to_dict() for f in findings]

        patched = self.store.patch_agent_discovery(
            agent_id,
            refreshed.to_dict(),
            [a.to_dict() for a in assets],
            cve_findings=cve_payload,
        )
        if patched is None:
            raise AssetOperationError("更新成功但写入快照失败")
        return patched

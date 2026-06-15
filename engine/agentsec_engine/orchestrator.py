"""ScanOrchestrator：调度扫描流水线。

流程（architecture.md 三·3）：
  discover → (exposure | cve) → reporter → commit replace
  - 异步推进度（≤10s 出进度+资产计数，不推 partial Finding）
  - 完成才 commit；取消/崩溃丢弃本次（NF-A1）
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, List, Optional

from .detectors.cve import CVEDetector
from .detectors.exposure import ExposureDetector, ScanTarget
from .discovery import discover_all
from .models import AssetType, ScanMeta
from .reporter import Reporter
from .store import SnapshotStore

ProgressCb = Callable[[dict], None]


class ScanOrchestrator:
    def __init__(self, store: SnapshotStore, rules_dir: Optional[str] = None,
                 cve_online: bool = True):
        self.store = store
        self.exposure = ExposureDetector(rules_dir=rules_dir)
        self.cve = CVEDetector()
        # 允许注入联网状态（演示 CVE 不可用）
        from .detectors.cve import RemoteOSVProvider
        self.cve.provider = RemoteOSVProvider(online=cve_online)
        self.reporter = Reporter()
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self, scope: str = "本机全部", scope_path: Optional[str] = None,
            on_progress: Optional[ProgressCb] = None, simulate_delay: bool = True) -> dict:
        """执行一次扫描。返回最终快照 dict；取消则返回 {"cancelled": True}。"""
        self._cancelled = False
        started = datetime.now()
        t0 = time.time()

        def progress(stage: str, percent: int, label: str, counts=None):
            if on_progress:
                on_progress({
                    "type": "progress",
                    "stage": stage,
                    "percent": percent,
                    "label": label,
                    "counts": counts or {},
                })

        # 1. 资产发现
        progress("discovery", 10, "正在发现本机 Agent 与资产…")
        if simulate_delay:
            time.sleep(0.4)
        agents, assets, atr_targets, adapter_status = discover_all(scope_path)
        if self._cancelled:
            return {"cancelled": True}

        counts = {
            "agents": len(agents),
            "mcp": sum(1 for a in assets if a.type == AssetType.MCP.value),
            "skills": sum(1 for a in assets if a.type == AssetType.SKILL.value),
        }
        progress("discovery", 35, "资产发现完成", counts)

        # 2. 暴露面检测（ATR + OpenClaw audit）
        progress("exposure", 55, "正在进行漏洞检测…", counts)
        targets = [ScanTarget(p, src, aids) for (p, src, aids) in atr_targets]
        total = len(targets) or 1

        def atr_file_progress(done: int, total_files: int) -> None:
            # 暴露面阶段占 55%–78%，按文件数平滑推进
            pct = 55 + int(23 * done / max(total_files, 1))
            progress("exposure", pct, f"漏洞检测中 ({done}/{total_files})…", counts)

        exposure_findings = self.exposure.scan(
            agents, targets, on_file_progress=atr_file_progress
        )
        if self._cancelled:
            return {"cancelled": True}

        # 3. CVE 检测（联网 OSV）
        progress("cve", 80, "正在匹配组件漏洞…", counts)
        if simulate_delay:
            time.sleep(0.4)
        deps = [a for a in assets if a.type == AssetType.DEPENDENCY.value]
        cve_findings, cve_status = self.cve.scan(deps)
        if self._cancelled:
            return {"cancelled": True}

        # 4. 汇总 + 落盘
        progress("report", 95, "正在生成结果…", counts)
        finished = datetime.now()
        meta = ScanMeta(
            started_at=started.strftime("%Y-%m-%d %H:%M:%S"),
            finished_at=finished.strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=max(1, int(time.time() - t0)),
            scope=scope,
            cve_status=cve_status,
        )
        snapshot = self.reporter.build_snapshot(
            meta, agents, assets, exposure_findings, cve_findings
        )
        self.store.commit_replace(snapshot)
        progress("done", 100, "扫描完成", counts)
        return snapshot.to_dict()

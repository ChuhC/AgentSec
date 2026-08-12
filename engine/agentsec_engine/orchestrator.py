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
from .models import AssetType, ScanMeta, ScanStatus
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

    def _is_cancelled(self) -> bool:
        return self._cancelled

    def run(self, scope: str = "本机全部", scope_path: Optional[str] = None,
            on_progress: Optional[ProgressCb] = None, simulate_delay: bool = True) -> dict:
        """执行一次扫描。返回最终快照 dict；取消则返回 {"cancelled": True}。"""
        started = datetime.now()
        t0 = time.time()

        def progress(stage: str, percent: int, label: str, counts=None):
            if self._cancelled:
                return
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
        if self._cancelled:
            return {"cancelled": True}
        def discovery_progress(done: int, total_adapters: int, found_agents, found_assets) -> None:
            pct = 10 + int(24 * done / max(total_adapters, 1))
            partial_counts = {
                "agents": len(found_agents),
                "mcp": sum(1 for a in found_assets if a.type == AssetType.MCP.value),
                "skills": sum(1 for a in found_assets if a.type == AssetType.SKILL.value),
            }
            progress(
                "discovery",
                pct,
                f"正在发现本机 Agent 与资产 ({done}/{total_adapters})…",
                partial_counts,
            )

        agents, assets, atr_targets, adapter_status = discover_all(
            scope_path,
            online=False,
            should_cancel=self._is_cancelled,
            on_progress=discovery_progress,
            check_updates=True,
        )
        if self._cancelled:
            return {"cancelled": True}

        counts = {
            "agents": len(agents),
            "mcp": sum(1 for a in assets if a.type == AssetType.MCP.value),
            "skills": sum(1 for a in assets if a.type == AssetType.SKILL.value),
        }
        progress("discovery", 35, "资产发现完成", counts)

        # 2. 暴露面检测（ATR + OpenClaw audit）
        progress("exposure", 55, "正在进行威胁检测…", counts)
        targets = [ScanTarget(p, src, aids) for (p, src, aids) in atr_targets]
        total = len(targets) or 1

        def atr_file_progress(done: int, total_files: int) -> None:
            if self._cancelled:
                return
            # 暴露面阶段占 55%–78%，按文件数平滑推进
            pct = 55 + int(23 * done / max(total_files, 1))
            progress("exposure", pct, f"威胁检测中 ({done}/{total_files})…", counts)

        exposure_findings = self.exposure.scan(
            agents,
            targets,
            on_file_progress=atr_file_progress,
            should_cancel=self._is_cancelled,
            run_openclaw_audit=scope_path is None,
        )
        if self._cancelled:
            return {"cancelled": True}

        # 3. CVE 检测（联网 OSV）
        progress("cve", 80, "正在匹配组件漏洞…", counts)
        if simulate_delay:
            time.sleep(0.4)
        if self._cancelled:
            return {"cancelled": True}
        deps = [a for a in assets if a.type == AssetType.DEPENDENCY.value]
        cve_findings, cve_status = self.cve.scan(deps, should_cancel=self._is_cancelled)
        if self._cancelled:
            return {"cancelled": True}

        # 4. 汇总 + 落盘
        progress("report", 95, "正在生成结果…", counts)
        finished = datetime.now()
        exposure_diag = self.exposure.last_diagnostics
        cve_diag = self.cve.last_diagnostics
        has_adapter_error = any(
            str(value).startswith("error") for value in adapter_status.values()
        )
        if not agents:
            scan_status = ScanStatus.NO_AGENTS.value
        elif (
            has_adapter_error
            or exposure_diag.get("status") != "ok"
            or cve_status != "ok"
        ):
            scan_status = ScanStatus.PARTIAL.value
        else:
            scan_status = ScanStatus.COMPLETE.value
        meta = ScanMeta(
            started_at=started.strftime("%Y-%m-%d %H:%M:%S"),
            finished_at=finished.strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=max(1, int(time.time() - t0)),
            scope=scope,
            scan_status=scan_status,
            adapter_status=adapter_status,
            exposure_status=str(exposure_diag.get("status") or "ok"),
            exposure_timed_out_count=len(
                exposure_diag.get("timed_out_paths") or []
            ),
            exposure_read_error_count=len(
                exposure_diag.get("read_error_paths") or []
            )
            + len(exposure_diag.get("worker_errors") or []),
            cve_status=cve_status,
            cve_scanned_count=int(cve_diag.get("queried") or 0),
            cve_skipped_count=int(cve_diag.get("skipped") or 0),
            cve_detail_error_count=int(cve_diag.get("detail_errors") or 0),
        )
        snapshot = self.reporter.build_snapshot(
            meta, agents, assets, exposure_findings, cve_findings
        )
        self.store.commit_replace(snapshot)
        progress("done", 100, "扫描完成", counts)
        return snapshot.to_dict()

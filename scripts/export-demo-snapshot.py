#!/usr/bin/env python3
"""导出 fixtures 演示快照为 JSON，供 README 截图脚本使用。"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

from agentsec_engine.data.fixtures import (  # noqa: E402
    build_agents,
    build_assets,
    build_cve_findings,
    build_exposure_findings,
)
from agentsec_engine.models import ScanMeta  # noqa: E402
from agentsec_engine.reporter import Reporter  # noqa: E402

OUT = ROOT / "app" / "scripts" / "fixtures" / "demo-snapshot.json"


def main() -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    meta = ScanMeta(
        scope="all",
        duration_seconds=12,
        finished_at=now,
        cve_status="ok",
        cve_scanned_count=24,
    )
    snap = Reporter().build_snapshot(
        meta=meta,
        agents=build_agents(),
        assets=build_assets(),
        exposure_findings=build_exposure_findings(),
        cve_findings=build_cve_findings(),
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snap.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()

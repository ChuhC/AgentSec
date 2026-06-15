"""Reporter：脱敏 + 聚合，产出 ScanSnapshot。

职责（architecture.md 二/三）：
  - 合并 ExposureDetector / CVEDetector 输出
  - 去重键：(source, check_id, path, line)
  - 落盘脱敏：凭证类仅留「检测到引用」+ 位置（NF-S2）
"""

from __future__ import annotations

import re
from typing import List

from .models import (
    Agent,
    Asset,
    CVEFinding,
    ExposureFinding,
    ScanMeta,
    ScanSnapshot,
)

# 脱敏（NF-S2）：凭证类仅保留前 4 位，其余以 … 替代
_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{4})[A-Za-z0-9]{6,}"),
    re.compile(r"(gh[pous]_[A-Za-z0-9]{4})[A-Za-z0-9]{6,}"),
    re.compile(r"(AKIA[A-Z0-9]{4})[A-Z0-9]{6,}"),
]

# key: value / key=value 形态：对值（≥6 字符）打码
_SECRET_KV = re.compile(
    r"""(?ix)
    ( "?(?:api[_-]?key|apikey|access[_-]?key|secret|client[_-]?secret
        |password|passwd|token|bearer|auth)[\w-]* "? \s* [:=] \s* "? )
    ( [^\s",}]{6,} )
    """,
)


def _mask_value(m: "re.Match") -> str:
    val = m.group(2)
    return m.group(1) + val[:4] + "…"


def _redact(text: str) -> str:
    if not text:
        return text
    out = text
    out = _SECRET_KV.sub(_mask_value, out)
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "…", out)
    return out


def _dedup_key(f: ExposureFinding):
    return (f.source, f.id, f.location)


class Reporter:
    def build_snapshot(
        self,
        meta: ScanMeta,
        agents: List[Agent],
        assets: List[Asset],
        exposure_findings: List[ExposureFinding],
        cve_findings: List[CVEFinding],
    ) -> ScanSnapshot:
        # 去重
        seen = set()
        deduped: List[ExposureFinding] = []
        for f in exposure_findings:
            k = _dedup_key(f)
            if k in seen:
                continue
            seen.add(k)
            # 脱敏
            f.evidence = _redact(f.evidence)
            f.impact = _redact(f.impact)
            deduped.append(f)

        return ScanSnapshot(
            meta=meta,
            agents=agents,
            assets=assets,
            exposure_findings=deduped,
            cve_findings=cve_findings,
        )

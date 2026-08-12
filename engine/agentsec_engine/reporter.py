"""Reporter：脱敏 + 聚合，产出 ScanSnapshot。

职责（architecture.md 二/三）：
  - 合并 ExposureDetector / CVEDetector 输出
  - 暴露面聚合键：(source, rule_id)；合并 agent_ids、locations、evidence
  - 落盘脱敏：凭证类仅留「检测到引用」+ 位置（NF-S2）
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any
from typing import Dict, List, Tuple

from .models import (
    Agent,
    Asset,
    CVEFinding,
    ExposureFinding,
    ScanMeta,
    ScanSnapshot,
    Severity,
)

# 脱敏（NF-S2）：凭证类仅保留前 4 位，其余以 … 替代
_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{4})[A-Za-z0-9]{6,}"),
    re.compile(r"(gh[pous]_[A-Za-z0-9]{4})[A-Za-z0-9]{6,}"),
    re.compile(r"(github_pat_[A-Za-z0-9_]{4})[A-Za-z0-9_]{8,}"),
    re.compile(r"(glpat-[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{6,}"),
    re.compile(r"(npm_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}"),
    re.compile(r"(xox[baprs]-[A-Za-z0-9-]{4})[A-Za-z0-9-]{8,}"),
    re.compile(r"(AIza[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{12,}"),
    re.compile(r"(AKIA[A-Z0-9]{4})[A-Z0-9]{6,}"),
]

# key: value / key=value 形态：对值（≥6 字符）打码
_SECRET_KV = re.compile(
    r"""(?ix)
    ( "?(?:api[_-]?key|apikey|access[_-]?key|secret|client[_-]?secret
        |password|passwd|token|auth|authorization|signature)[\w-]* "?
        \s* [:=] \s* "? )
    ( [^\s"',}&]{6,} )
    """,
)
_URL_SECRET = re.compile(
    r"""(?ix)
    ([?&](?:api[_-]?key|apikey|access[_-]?key|secret|client[_-]?secret
      |password|passwd|token|auth|authorization|signature)=)
    ([^&#\s]{4,})
    """
)
_URL_USERINFO = re.compile(r"(https?://[^/\s:@]+:)([^@/\s]{4,})(@)", re.I)
_BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]{8,})")
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)


def _mask_value(m: "re.Match") -> str:
    val = m.group(2)
    return m.group(1) + val[:4] + "…"


def _redact(text: str) -> str:
    if not text:
        return text
    out = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    out = _BEARER.sub(lambda m: m.group(1) + "[REDACTED]", out)
    out = _JWT.sub("[REDACTED JWT]", out)
    out = _URL_SECRET.sub(
        lambda m: m.group(1) + m.group(2)[:4] + "…", out
    )
    out = _URL_USERINFO.sub(
        lambda m: m.group(1) + "[REDACTED]" + m.group(3), out
    )
    out = _SECRET_KV.sub(_mask_value, out)
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "…", out)
    return out


def redact_snapshot_dict(value: Any) -> Any:
    """递归脱敏快照的所有字符串字段，包括 Agent/Asset 元数据。"""
    value = deepcopy(value)

    def walk(item):
        if isinstance(item, str):
            return _redact(item)
        if isinstance(item, list):
            return [walk(v) for v in item]
        if isinstance(item, dict):
            return {k: walk(v) for k, v in item.items()}
        return item

    return walk(value)


_AGG_KEY = lambda f: (f.source, f.id)  # noqa: E731
_MAX_EVIDENCE_PARTS = 3
_SEV_RANK = {
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
}


def _finding_locations(f: ExposureFinding) -> List[str]:
    if f.locations:
        return list(f.locations)
    return [f.location] if f.location else []


def _merge_exposure_group(group: List[ExposureFinding]) -> ExposureFinding:
    """同 source+rule_id 的多文件命中合并为一条。"""
    base = group[0]
    agent_ids = sorted({aid for f in group for aid in f.agent_ids})
    locations: List[str] = []
    seen_loc = set()
    for f in group:
        for loc in _finding_locations(f):
            if loc and loc not in seen_loc:
                seen_loc.add(loc)
                locations.append(loc)
    evidences: List[str] = []
    seen_ev = set()
    for f in group:
        ev = _redact(f.evidence)
        if ev and ev not in seen_ev:
            seen_ev.add(ev)
            evidences.append(ev)
    if len(evidences) > _MAX_EVIDENCE_PARTS:
        evidence = "\n---\n".join(evidences[:_MAX_EVIDENCE_PARTS])
        extra = len(evidences) - _MAX_EVIDENCE_PARTS
        if extra:
            evidence += f"\n… 另有 {extra} 处命中"
    else:
        evidence = "\n---\n".join(evidences)
    severity = max(
        (f.severity for f in group),
        key=lambda s: _SEV_RANK.get(s, 0),
    )
    return ExposureFinding(
        id=base.id,
        title=base.title,
        severity=severity,
        category=base.category,
        source=base.source,
        agent_ids=agent_ids,
        impact=_redact(base.impact),
        evidence=evidence,
        recommendation=base.recommendation,
        plain_explanation=base.plain_explanation,
        location=locations[0] if locations else base.location,
        locations=locations,
        tags=base.tags,
    )


def _aggregate_exposure(findings: List[ExposureFinding]) -> List[ExposureFinding]:
    groups: Dict[Tuple[str, str], List[ExposureFinding]] = {}
    for f in findings:
        groups.setdefault(_AGG_KEY(f), []).append(f)
    return [_merge_exposure_group(g) for g in groups.values()]


class Reporter:
    def build_snapshot(
        self,
        meta: ScanMeta,
        agents: List[Agent],
        assets: List[Asset],
        exposure_findings: List[ExposureFinding],
        cve_findings: List[CVEFinding],
    ) -> ScanSnapshot:
        aggregated = _aggregate_exposure(exposure_findings)

        return ScanSnapshot(
            meta=meta,
            agents=agents,
            assets=assets,
            exposure_findings=aggregated,
            cve_findings=cve_findings,
        )

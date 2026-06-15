"""CVEDetector：组件 CVE（联网 OSV）。

Provider 接口（architecture.md 五·4）：
  - RemoteOSVProvider : MVP，调用 osv.dev /v1/query（必须联网；失败则 CVE 不可用 NF-A2）
  - LocalCVEStore     : vNext 占位

实现：纯 stdlib urllib 请求 OSV，cvss 库解析 CVSS 向量为 base_score。
联网失败（超时/连接错误）→ 返回 cve_status=unavailable，不阻塞暴露面。
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from ..models import Asset, CVEFinding, CVEItem, CVEStatus, Severity

OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 8

# 组件类型 → OSV ecosystem
_ECOSYSTEM = {
    "npm": "npm",
    "pip": "PyPI",
    "pypi": "PyPI",
    "PyPI": "PyPI",
    "maven": "Maven",
    "Maven": "Maven",
    "go": "Go",
    "cargo": "crates.io",
}

_SEV_TEXT = {
    "CRITICAL": Severity.HIGH.value,
    "HIGH": Severity.HIGH.value,
    "MODERATE": Severity.MEDIUM.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
}
_SEV_RANK = {Severity.HIGH.value: 3, Severity.MEDIUM.value: 2, Severity.LOW.value: 1}


def _cvss_score(vectors: List[str]) -> float:
    """从 CVSS 向量取 base_score（优先 v3/v4，回退 v2）。"""
    for vec in vectors:
        try:
            if vec.startswith("CVSS:3"):
                from cvss import CVSS3

                return float(CVSS3(vec).base_score)
            if vec.startswith("CVSS:4"):
                from cvss import CVSS4

                return float(CVSS4(vec).base_score)
            from cvss import CVSS2

            return float(CVSS2(vec).base_score)
        except Exception:  # noqa: BLE001
            continue
    return 0.0


def _severity_from(vuln: dict, cvss: float) -> str:
    text = (vuln.get("database_specific") or {}).get("severity")
    if text and text.upper() in _SEV_TEXT:
        return _SEV_TEXT[text.upper()]
    if cvss >= 7.0:
        return Severity.HIGH.value
    if cvss >= 4.0:
        return Severity.MEDIUM.value
    if cvss > 0:
        return Severity.LOW.value
    return Severity.LOW.value


def _cve_id(vuln: dict) -> str:
    for a in vuln.get("aliases", []) or []:
        if str(a).startswith("CVE-"):
            return a
    return vuln.get("id", "")


def _fixed_version(vuln: dict) -> Optional[str]:
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def _published(vuln: dict) -> str:
    p = vuln.get("published") or vuln.get("modified") or ""
    return p[:10]


class CVEProvider:
    def query(self, dependencies: List[Asset]) -> Tuple[List[CVEFinding], str]:
        raise NotImplementedError


class RemoteOSVProvider(CVEProvider):
    def __init__(self, online: bool = True):
        # online=False 可强制模拟离线（演示 CVE 不可用态）
        self.online = online and not os.environ.get("AGENTSEC_CVE_OFFLINE")

    def _query_one(self, name: str, version: str, ecosystem: str) -> List[dict]:
        body = json.dumps(
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        ).encode("utf-8")
        req = urllib.request.Request(
            OSV_URL, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("vulns", []) or []

    def query(self, dependencies: List[Asset]) -> Tuple[List[CVEFinding], str]:
        if not self.online:
            return [], CVEStatus.UNAVAILABLE.value

        findings: List[CVEFinding] = []
        for dep in dependencies:
            ecosystem = _ECOSYSTEM.get(dep.ecosystem or "")
            if not ecosystem or not dep.version:
                continue
            try:
                vulns = self._query_one(dep.name, dep.version, ecosystem)
            except (urllib.error.URLError, TimeoutError, OSError):
                # 任一请求网络失败 → 整体 CVE 不可用（NF-A2）
                return [], CVEStatus.UNAVAILABLE.value
            except Exception:  # noqa: BLE001
                continue

            cves: List[CVEItem] = []
            for v in vulns:
                vectors = [s.get("score", "") for s in (v.get("severity") or [])]
                score = _cvss_score(vectors)
                sev = _severity_from(v, score)
                cves.append(
                    CVEItem(
                        cve_id=_cve_id(v),
                        severity=sev,
                        cvss=round(score, 1),
                        summary=(v.get("summary") or v.get("details") or "").strip()[:200],
                    )
                )
            if not cves:
                continue
            # 同一 CVE 可能经 CVE/GHSA 别名重复出现 → 按 cve_id 去重，保留评分更高者
            dedup: dict = {}
            for c in cves:
                cur = dedup.get(c.cve_id)
                if cur is None or c.cvss > cur.cvss:
                    dedup[c.cve_id] = c
            cves = list(dedup.values())
            cves.sort(key=lambda c: c.cvss, reverse=True)
            top_sev = max((c.severity for c in cves), key=lambda s: _SEV_RANK.get(s, 0))
            fixed = next((_fixed_version(v) for v in vulns if _fixed_version(v)), None)
            dates = [d for d in (_published(v) for v in vulns) if d]
            findings.append(
                CVEFinding(
                    id="cve-" + dep.name,
                    component=dep.name,
                    component_type=ecosystem,
                    current_version=dep.version,
                    fixed_version=fixed,
                    severity=top_sev,
                    agent_ids=[dep.agent_id],
                    first_seen=min(dates) if dates else "",
                    cves=cves,
                    upgrade_advice=(
                        "建议升级到 %s，可修复上述已知漏洞。" % fixed
                        if fixed
                        else "暂无官方修复版本，建议关注上游更新或评估替代组件。"
                    ),
                )
            )

        # 组件整体严重度排序：高→中→低
        findings.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        return findings, CVEStatus.OK.value


class CVEDetector:
    def __init__(self, provider: Optional[CVEProvider] = None):
        self.provider = provider or RemoteOSVProvider(online=True)

    def scan(self, dependencies: List[Asset]) -> Tuple[List[CVEFinding], str]:
        try:
            return self.provider.query(dependencies)
        except Exception:  # noqa: BLE001 - 兜底：异常视为 CVE 不可用
            return [], CVEStatus.UNAVAILABLE.value

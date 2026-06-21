"""CVEDetector：组件 CVE（联网 OSV）。

Provider 接口（architecture.md 五·4）：
  - RemoteOSVProvider : MVP，调用 osv.dev /v1/querybatch（必须联网；失败则 CVE 不可用 NF-A2）
  - LocalCVEStore     : vNext 占位

实现：纯 stdlib urllib 请求 OSV，cvss 库解析 CVSS 向量为 base_score。
联网失败（超时/连接错误）→ 返回 cve_status=unavailable，不阻塞暴露面。
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

from ..models import Asset, CVEFinding, CVEItem, CVEStatus, Severity

OSV_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_TIMEOUT = 8
_TIMEOUT_BATCH = 90
_TIMEOUT_VULN = 12
_BATCH_SIZE = 128
_HYDRATE_WORKERS = 8

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


def _vuln_ids(vuln: dict) -> Tuple[str, str]:
    """返回 (展示用主 id, 公告 id)。主 id 优先 CVE，其次 GHSA，最后 OSV id。"""
    cve = ""
    ghsa = ""
    osv_id = str(vuln.get("id") or "")
    for a in vuln.get("aliases", []) or []:
        s = str(a)
        if s.startswith("CVE-") and not cve:
            cve = s
        elif s.startswith("GHSA-") and not ghsa:
            ghsa = s
    if not cve and osv_id.startswith("CVE-"):
        cve = osv_id
    primary = cve or ghsa or osv_id
    advisory = ""
    if cve and osv_id and osv_id != cve:
        advisory = osv_id
    elif not cve and ghsa:
        advisory = ghsa
    return primary, advisory


def _vuln_is_stub(vuln: dict) -> bool:
    """OSV querybatch 仅返回 id/modified，需二次拉取完整记录。"""
    if not vuln.get("id"):
        return False
    return not (vuln.get("aliases") or vuln.get("summary") or vuln.get("details"))


def _vuln_summary(vuln: dict) -> str:
    text = (vuln.get("summary") or vuln.get("details") or "").strip()
    if len(text) > 8000:
        return text[:8000] + "…"
    return text


_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
_SEMVER_START_RE = re.compile(r"^v?\d+\.\d+")
_RELEASE_TAG_RE = re.compile(r"/releases/tag/v?([^/?#]+)")


def _looks_like_version(val: str) -> bool:
    val = val.strip()
    if not val or _GIT_SHA_RE.match(val):
        return False
    return bool(_SEMVER_START_RE.match(val))


def _fixed_version_from_refs(vuln: dict) -> Optional[str]:
    for ref in vuln.get("references") or []:
        url = str(ref.get("url") or "")
        m = _RELEASE_TAG_RE.search(url)
        if m and _looks_like_version(m.group(1)):
            return m.group(1).lstrip("v")
    return None


def _fixed_version(vuln: dict) -> Optional[str]:
    """修复版本：优先 ECOSYSTEM 语义化版本，忽略 GIT commit hash。"""
    eco: List[str] = []
    other: List[str] = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            rtype = str(rng.get("type") or "")
            for ev in rng.get("events", []) or []:
                if "fixed" not in ev:
                    continue
                val = str(ev["fixed"]).strip()
                if not val:
                    continue
                if rtype == "ECOSYSTEM":
                    eco.append(val)
                elif rtype != "GIT":
                    other.append(val)
    for pool in (eco, other):
        for val in pool:
            if _looks_like_version(val):
                return val.lstrip("v")
    ref_ver = _fixed_version_from_refs(vuln)
    if ref_ver:
        return ref_ver
    return None


def _version_sort_key(v: str):
    parts = re.split(r"[.\-+]", v.lstrip("v"))
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return key


def _best_fixed_version(vulns: List[dict]) -> Optional[str]:
    candidates: List[str] = []
    for v in vulns:
        fv = _fixed_version(v)
        if fv and _looks_like_version(fv):
            candidates.append(fv.lstrip("v"))
    if not candidates:
        return None
    return max(candidates, key=_version_sort_key)


def _published(vuln: dict) -> str:
    p = vuln.get("published") or vuln.get("modified") or ""
    return p[:10]


def _reference_url(vuln: dict) -> str:
    """公告/漏洞详情页 URL（优先 OSV references，回退 NVD / GHSA / osv.dev）。"""
    primary, advisory = _vuln_ids(vuln)
    refs = vuln.get("references") or []
    cve_id = primary if primary.startswith("CVE-") else ""

    for ref in refs:
        url = str(ref.get("url") or "")
        if not url:
            continue
        if ref.get("type") == "ADVISORY":
            if cve_id and cve_id in url:
                return url
    for ref in refs:
        url = str(ref.get("url") or "")
        if url and ref.get("type") == "ADVISORY":
            return url
    for ref in refs:
        url = str(ref.get("url") or "")
        if url and ("nvd.nist.gov" in url or "github.com/advisories" in url):
            return url

    if cve_id:
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    osv_key = advisory or str(vuln.get("id") or "")
    if osv_key.startswith("GHSA-"):
        return f"https://github.com/advisories/{osv_key}"
    if osv_key:
        return "https://osv.dev/vulnerability/" + urllib.parse.quote(osv_key, safe="")
    return ""


def _vulns_to_cves(vulns: List[dict]) -> List[CVEItem]:
    cves: List[CVEItem] = []
    for v in vulns:
        vectors = [s.get("score", "") for s in (v.get("severity") or [])]
        score = _cvss_score(vectors)
        sev = _severity_from(v, score)
        primary, advisory = _vuln_ids(v)
        cves.append(
            CVEItem(
                cve_id=primary,
                severity=sev,
                cvss=round(score, 1),
                summary=_vuln_summary(v),
                advisory_id=advisory,
                reference_url=_reference_url(v),
            )
        )
    dedup: dict = {}
    for c in cves:
        cur = dedup.get(c.cve_id)
        if cur is None or c.cvss > cur.cvss:
            dedup[c.cve_id] = c
    cves = list(dedup.values())
    cves.sort(key=lambda c: c.cvss, reverse=True)
    return cves


def _finding_from_dep(dep: Asset, vulns: List[dict], ecosystem: str) -> Optional[CVEFinding]:
    cves = _vulns_to_cves(vulns)
    if not cves:
        return None
    top_sev = max((c.severity for c in cves), key=lambda s: _SEV_RANK.get(s, 0))
    fixed = _best_fixed_version(vulns)
    dates = [d for d in (_published(v) for v in vulns) if d]
    return CVEFinding(
        id="cve-" + dep.id.replace(f"{dep.agent_id}-dep-", ""),
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


class CVEProvider:
    def query(
        self,
        dependencies: List[Asset],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Tuple[List[CVEFinding], str]:
        raise NotImplementedError


class RemoteOSVProvider(CVEProvider):
    def __init__(self, online: bool = True):
        # online=False 可强制模拟离线（演示 CVE 不可用态）
        self.online = online and not os.environ.get("AGENTSEC_CVE_OFFLINE")

    def _fetch_vuln(self, vuln_id: str) -> dict:
        url = OSV_VULN_URL + urllib.parse.quote(vuln_id, safe="")
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=_TIMEOUT_VULN) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _hydrate_vulns(
        self,
        vulns: List[dict],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> List[dict]:
        """querybatch 返回 stub 时，按 id 拉取 /v1/vulns/{id} 补全 CVE 别名与描述。"""
        if not vulns:
            return []
        cache: Dict[str, dict] = {}
        to_fetch: List[str] = []
        for v in vulns:
            vid = str(v.get("id") or "")
            if not vid:
                continue
            if not _vuln_is_stub(v):
                cache[vid] = v
            elif vid not in cache and vid not in to_fetch:
                to_fetch.append(vid)

        if to_fetch:
            workers = min(_HYDRATE_WORKERS, len(to_fetch))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._fetch_vuln, vid): vid for vid in to_fetch}
                for fut in as_completed(futures):
                    if should_cancel and should_cancel():
                        break
                    vid = futures[fut]
                    try:
                        cache[vid] = fut.result()
                    except Exception:  # noqa: BLE001
                        cache[vid] = {"id": vid}

        out: List[dict] = []
        for v in vulns:
            vid = str(v.get("id") or "")
            out.append(cache.get(vid, v))
        return out

    def _query_one(self, name: str, version: str, ecosystem: str) -> List[dict]:
        body = json.dumps(
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        ).encode("utf-8")
        req = urllib.request.Request(
            OSV_URL, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vulns = data.get("vulns", []) or []
        return self._hydrate_vulns(vulns)

    def _query_batch(
        self,
        queries: List[Tuple[str, str, str]],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> List[List[dict]]:
        """queries: [(name, version, ecosystem), ...]"""
        if not queries:
            return []
        all_vulns: List[List[dict]] = []
        for i in range(0, len(queries), _BATCH_SIZE):
            if should_cancel and should_cancel():
                break
            chunk = queries[i : i + _BATCH_SIZE]
            body = json.dumps(
                {
                    "queries": [
                        {
                            "version": ver,
                            "package": {"name": name, "ecosystem": eco},
                        }
                        for name, ver, eco in chunk
                    ]
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                OSV_BATCH_URL,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT_BATCH) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("results", []):
                stub_vulns = item.get("vulns") or []
                all_vulns.append(
                    self._hydrate_vulns(stub_vulns, should_cancel=should_cancel)
                )
        return all_vulns

    def query(
        self,
        dependencies: List[Asset],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Tuple[List[CVEFinding], str]:
        if not self.online:
            return [], CVEStatus.UNAVAILABLE.value

        indexed: List[Tuple[Asset, str]] = []
        for dep in dependencies:
            if should_cancel and should_cancel():
                return [], CVEStatus.OK.value
            ecosystem = _ECOSYSTEM.get(dep.ecosystem or "")
            if not ecosystem or not dep.version:
                continue
            indexed.append((dep, ecosystem))

        if not indexed:
            return [], CVEStatus.OK.value

        try:
            if len(indexed) == 1:
                if should_cancel and should_cancel():
                    return [], CVEStatus.OK.value
                dep, eco = indexed[0]
                vulns_list = [self._query_one(dep.name, dep.version, eco)]
            else:
                vulns_list = self._query_batch(
                    [(d.name, d.version, eco) for d, eco in indexed],
                    should_cancel=should_cancel,
                )
        except (urllib.error.URLError, TimeoutError, OSError):
            return [], CVEStatus.UNAVAILABLE.value

        if should_cancel and should_cancel():
            return [], CVEStatus.OK.value

        findings: List[CVEFinding] = []
        for (dep, eco), vulns in zip(indexed, vulns_list):
            try:
                finding = _finding_from_dep(dep, vulns, eco)
            except Exception:  # noqa: BLE001
                continue
            if finding:
                findings.append(finding)

        findings.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        return findings, CVEStatus.OK.value


class CVEDetector:
    def __init__(self, provider: Optional[CVEProvider] = None):
        self.provider = provider or RemoteOSVProvider(online=True)

    def scan(
        self,
        dependencies: List[Asset],
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Tuple[List[CVEFinding], str]:
        try:
            return self.provider.query(dependencies, should_cancel=should_cancel)
        except Exception:  # noqa: BLE001 - 兜底：异常视为 CVE 不可用
            return [], CVEStatus.UNAVAILABLE.value

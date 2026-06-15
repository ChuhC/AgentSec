"""核心领域对象（对齐 architecture.md 二·3）。

全部使用 dataclass，并提供 to_dict() 以便 IPC 序列化为 JSON。
保持 Python 3.8 兼容（typing.Optional/List/Dict，不用 X | Y 语法）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    """UI 三档严重度 + 安全/信息。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"
    INFO = "info"


class AssetType(str, Enum):
    MCP = "mcp"
    SKILL = "skill"
    KNOWLEDGE = "knowledge"
    DEPENDENCY = "dependency"


class AssetStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UPDATABLE = "updatable"


class FindingSource(str, Enum):
    """暴露面 Finding 来源（去重键之一，并用于 Step7 定位 Tab）。"""

    SKILL = "skill"
    MCP = "mcp"
    AGENT_CONFIG = "agent_config"
    KNOWLEDGE = "knowledge"
    OPENCLAW_AUDIT = "openclaw_audit"


class CVEStatus(str, Enum):
    """CVE 管线状态：联网失败时 unavailable（NF-A2）。"""

    OK = "ok"
    UNAVAILABLE = "unavailable"


def _enum_value(v):
    return v.value if isinstance(v, Enum) else v


@dataclass
class PermissionEntry:
    """权限条目（含来源类型，供 Step7 权限雷达 + 弹窗聚合）。"""

    id: str
    name: str  # 例：执行 Shell 命令
    category: str  # 文件 / Shell / 网络 / 工具 / 知识库
    source: str  # FindingSource value
    source_label: str  # 例：Docker MCP / Agent 默认
    severity: str  # Severity value

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Asset:
    """MCP / Skill / 知识库 / 依赖。"""

    id: str
    agent_id: str
    type: str  # AssetType value
    name: str
    version: Optional[str] = None
    latest_version: Optional[str] = None
    status: str = AssetStatus.ENABLED.value
    purpose: str = ""  # 一句话用途
    source: str = ""  # 来源/配置出处
    ecosystem: Optional[str] = None  # 依赖组件的包生态（npm / PyPI / Maven），供 OSV 查询
    # 真实管理操作执行上下文（B1：经 npm/pip 等包管理器）。为空则走 MVP 模拟。
    manager: Optional[str] = None  # npm / pip
    install_path: Optional[str] = None  # 包管理器执行的工作目录
    package_name: Optional[str] = None  # 真实包名（默认取 name）
    # 真机文件句柄：skill 的 SKILL.md 路径；mcp 的 config 文件路径 + 服务键
    path: Optional[str] = None
    config_key: Optional[str] = None
    permissions: List[PermissionEntry] = field(default_factory=list)
    can_update: bool = False
    can_disable: bool = True
    can_uninstall: bool = True

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


@dataclass
class Agent:
    """Hermes / OpenClaw 实例。"""

    id: str
    name: str
    kind: str  # hermes / openclaw
    version: str
    enabled: bool = True
    description: str = ""
    latest_version: Optional[str] = None
    listen_ports: List[str] = field(default_factory=list)
    # Agent 配置级别的默认权限（权限雷达/弹窗的「Agent 配置」分组）
    permissions: List[PermissionEntry] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ExposureFinding:
    """暴露面 / 基线 / Prompt 注入发现。"""

    id: str  # 保留 ATR-YYYY-NNNNN 或内置 check id
    title: str
    severity: str  # Severity value
    category: str  # 网络暴露 / 权限与访问控制 / 输入校验 ...
    source: str  # FindingSource value
    agent_ids: List[str] = field(default_factory=list)
    impact: str = ""  # 影响说明
    evidence: str = ""  # 证据（已脱敏）
    recommendation: str = ""  # 推荐操作
    plain_explanation: str = ""  # 通俗说明（给普通用户）
    location: str = ""  # 主位置（首条命中，向后兼容）
    locations: List[str] = field(default_factory=list)  # 全部命中路径
    tags: List[str] = field(default_factory=list)  # owasp_agentic 等

    def to_dict(self) -> Dict:
        d = asdict(self)
        # 旧快照无 locations 时由 location 回填
        if not d.get("locations") and d.get("location"):
            d["locations"] = [d["location"]]
        return d


@dataclass
class CVEItem:
    cve_id: str
    severity: str  # Severity value
    cvss: float
    summary: str


@dataclass
class CVEFinding:
    """组件 CVE 匹配结果。"""

    id: str
    component: str
    component_type: str  # Maven / npm / pip ...
    current_version: str
    fixed_version: Optional[str]
    severity: str  # 组件整体最高严重度
    agent_ids: List[str] = field(default_factory=list)
    first_seen: str = ""
    cves: List[CVEItem] = field(default_factory=list)
    upgrade_advice: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


@dataclass
class ScanMeta:
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: int = 0
    scope: str = "本机全部"
    cve_status: str = CVEStatus.OK.value
    cve_scanned_count: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanSnapshot:
    """最近一次完整扫描快照（脱敏后）。SnapshotStore 唯一读源。"""

    schema_version: int = 1
    meta: ScanMeta = field(default_factory=ScanMeta)
    agents: List[Agent] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    exposure_findings: List[ExposureFinding] = field(default_factory=list)
    cve_findings: List[CVEFinding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "schema_version": self.schema_version,
            "meta": self.meta.to_dict(),
            "agents": [a.to_dict() for a in self.agents],
            "assets": [a.to_dict() for a in self.assets],
            "exposure_findings": [f.to_dict() for f in self.exposure_findings],
            "cve_findings": [c.to_dict() for c in self.cve_findings],
        }

    # ---- 派生统计（供 UI 概览，避免前端重复计算口径）----

    def exposure_counts(self) -> Dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for f in self.exposure_findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def cve_counts(self) -> Dict[str, int]:
        high = sum(1 for c in self.cve_findings if c.severity == Severity.HIGH.value)
        medium = sum(1 for c in self.cve_findings if c.severity == Severity.MEDIUM.value)
        affected = sum(1 for c in self.cve_findings if c.cves)
        return {"high": high, "medium": medium, "affected_components": affected}

    def asset_counts(self) -> Dict[str, int]:
        return {
            "agents": len(self.agents),
            "mcp": sum(1 for a in self.assets if a.type == AssetType.MCP.value),
            "skills": sum(1 for a in self.assets if a.type == AssetType.SKILL.value),
            "knowledge": sum(1 for a in self.assets if a.type == AssetType.KNOWLEDGE.value),
            "updatable": sum(1 for a in self.assets if a.status == AssetStatus.UPDATABLE.value),
        }

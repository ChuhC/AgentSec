"""ExposureDetector：暴露面 / 基线 / Prompt 注入。

组成（architecture.md 附录 C）：
  - ATREngine            : pyATR（内置 459 条规则，Layer1 = regex/pattern，纯离线）
  - OpenClawAuditCollector: wrap `openclaw security audit --json`（占位）

MVP 规则子集（见 docs/engine/atr-mvp-rules.md）：
  默认启用 stable + experimental 中 severity∈{critical,high,medium}、可静态扫描目标
  （mcp/skill/both）的规则，约 276 条（排除 2 条高误报）；experimental 的 critical/high
  另要求 confidence∈{high, medium-high}，medium 严重度 experimental 全量纳入。

pyatr 需 Python ≥ 3.10；导入失败时（如 3.8）自动降级，由上层回落到 fixture。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

from ..models import Agent, ExposureFinding, FindingSource, Severity
from ..threat_whitelist import is_whitelisted_path

try:  # pyatr 仅在 3.10+ 可用
    from pyatr import ATREngine as _PyATR, AgentEvent as _AgentEvent

    _PYATR_OK = True
except Exception:  # noqa: BLE001
    _PYATR_OK = False

_STATIC_TARGETS = {"mcp", "skill", "both"}

# 纳入 critical / high / medium（不含 low/info）
_SEV_INCLUDED = frozenset({"critical", "high", "medium"})
# experimental 规则额外要求较高置信度，控制误报
_CONF_INCLUDED = frozenset({"high", "medium-high"})

# MVP 排除：对 SKILL.md 静态扫描误报率过高的宽泛规则（见 docs/engine/atr-mvp-rules.md）
# ATR-2026-00001 — Indirect Prompt Injection via External Content：正常 skill 文档常描述外部输入
# ATR-2026-00030 — Cross-Agent Attack Detection：多 agent 协作文档触发面过宽
_EXCLUDED_RULE_IDS = frozenset({
    "ATR-2026-00001",
    "ATR-2026-00030",
})

# 单文件喂给 ATR 的最大字符数（性能护栏；注入特征通常靠前）
_MAX_SCAN_CHARS = 65536

# SKILL.md YAML frontmatter 剥离（--- ... ---），避免元数据 boilerplate 误报
_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n?", re.DOTALL)
_MIN_SKILL_BODY_CHARS = 32

# ATR 类别（kebab）→ agentSec 中文类别
_CAT_ZH = {
    "prompt-injection": "Prompt 注入",
    "agent-manipulation": "Agent 操纵",
    "tool-poisoning": "工具投毒",
    "context-exfiltration": "上下文外泄",
    "skill-compromise": "Skill 风险",
    "privilege-escalation": "权限提升",
    "excessive-autonomy": "过度自治",
    "model-abuse": "模型滥用",
    "data-poisoning": "数据投毒",
    "model-security": "模型安全",
}

# 给普通用户的通俗说明（按类别）
_CAT_PLAIN = {
    "prompt-injection": "有人可能往这段内容里藏了「命令」，诱导 AI 助手不听你的话、去做危险操作。建议清理可疑内容或限制这个来源。",
    "agent-manipulation": "这段内容试图操纵 AI 助手改变它的行为或目标，可能让它做你没要求的事。",
    "tool-poisoning": "工具/插件的描述里被植入了隐藏指令，可能在你不知情时触发危险动作。",
    "context-exfiltration": "这里存在把你的密钥、密码或敏感信息悄悄外传的风险。",
    "skill-compromise": "这个技能可能被做了手脚，比如远程下载并执行脚本，存在被投毒的风险。",
    "privilege-escalation": "存在获取超出必要范围权限的风险，建议收紧权限。",
    "excessive-autonomy": "AI 助手被授予了过大的自主权，可能在无人确认时执行高风险操作。",
    "model-abuse": "存在滥用模型生成恶意内容的迹象。",
    "data-poisoning": "知识库/数据可能被植入了误导性内容。",
    "model-security": "存在试图提取系统提示词等模型安全相关风险。",
}

_CAT_RECO = {
    "prompt-injection": "移除或隔离可疑内容，对外部输入做指令过滤，并限制该来源的信任级别。",
    "agent-manipulation": "审查该来源内容，禁用可疑配置，必要时收紧 Agent 行为边界。",
    "tool-poisoning": "核查该工具/MCP 的描述与来源，移除隐藏指令，仅保留可信工具。",
    "context-exfiltration": "立即排查外传目标，撤销可能泄露的凭证，禁止向未知地址发送敏感数据。",
    "skill-compromise": "停用该 Skill，核实来源与发布者，避免运行远程拉取的脚本。",
    "privilege-escalation": "遵循最小权限原则，收窄该组件的权限范围。",
    "excessive-autonomy": "为高风险操作增加人工确认，限制自主执行范围。",
    "model-abuse": "限制相关能力并加强内容审查。",
    "data-poisoning": "校验知识库来源，移除不可信内容。",
    "model-security": "限制系统提示词暴露面，加固模型访问控制。",
}


def _map_severity(atr_sev: str) -> str:
    s = (atr_sev or "").lower()
    if s in ("critical", "high"):
        return Severity.HIGH.value
    if s == "medium":
        return Severity.MEDIUM.value
    return Severity.LOW.value


def _preprocess_skill_text(path: str, text: str) -> str:
    """剥离 SKILL.md YAML frontmatter，仅扫描正文。"""
    if not path.endswith("SKILL.md"):
        return text
    return _FRONTMATTER_RE.sub("", text, count=1).strip()


def _locate(text: str, patterns) -> Tuple[str, str]:
    """用命中的正则在原文中定位真实片段与行号，作为证据。

    返回 (location_suffix, snippet)。
    """
    for pat in patterns or []:
        try:
            m = re.search(pat, text)
        except re.error:
            continue
        if m:
            start = m.start()
            line = text.count("\n", 0, start) + 1
            snippet = m.group(0).replace("\n", " ").strip()
            if len(snippet) > 160:
                snippet = snippet[:160] + "…"
            return (":" + str(line), snippet)
    return ("", "")


def _rule_in_subset(
    rule,
    *,
    include_experimental: bool,
    high_severity_only: bool,
) -> bool:
    """是否纳入当前扫描子集。"""
    tags = getattr(rule, "tags", None) or {}
    if tags.get("scan_target") not in _STATIC_TARGETS:
        return False
    status = getattr(rule, "status", None)
    if status == "stable":
        pass
    elif status == "experimental" and include_experimental:
        pass
    else:
        return False
    if high_severity_only:
        sev = (getattr(rule, "severity", None) or "").lower()
        if sev not in _SEV_INCLUDED:
            return False
        if (
            status == "experimental"
            and sev in ("critical", "high")
            and tags.get("confidence") not in _CONF_INCLUDED
        ):
            return False
    return True


class ATREngine:
    """pyATR 封装：加载内置规则，按子集过滤后对文件文本静态评估。"""

    def __init__(
        self,
        include_experimental: bool = True,
        high_severity_only: bool = True,
    ):
        self.available = _PYATR_OK
        self._engine = None
        self._subset_ids = set()
        self._rule_by_id: Dict[str, object] = {}
        if not self.available:
            return
        self._engine = _PyATR()
        self._engine.load_bundled_rules()
        for r in self._engine.rules:
            self._rule_by_id[r.id] = r
            if _rule_in_subset(
                r,
                include_experimental=include_experimental,
                high_severity_only=high_severity_only,
            ):
                self._subset_ids.add(r.id)
        self._subset_ids -= _EXCLUDED_RULE_IDS
        # 性能：原地裁剪规则列表，evaluate 只跑子集（459 → ~276，详见 atr-mvp-rules.md）。
        try:
            self._engine._rules[:] = [
                r for r in self._engine._rules if r.id in self._subset_ids
            ]
        except Exception:  # noqa: BLE001 - 裁剪失败则退回全量+结果过滤
            pass

    @property
    def subset_size(self) -> int:
        return len(self._subset_ids)

    def scan_file(
        self, path: str, text: str, source: str, agent_ids: List[str]
    ) -> List[ExposureFinding]:
        if not self.available or not text:
            return []
        # 截断超大文件，防止个别规则正则在大文本上退化（性能护栏）
        if len(text) > _MAX_SCAN_CHARS:
            text = text[:_MAX_SCAN_CHARS]
        event = _AgentEvent(content=text, fields={"content": text})
        out: List[ExposureFinding] = []
        seen = set()
        for m in self._engine.evaluate(event):
            if m.rule_id not in self._subset_ids or m.rule_id in seen:
                continue
            seen.add(m.rule_id)
            out.append(self._to_finding(m, path, text, source, agent_ids))
        return out

    def _to_finding(self, m, path, text, source, agent_ids) -> ExposureFinding:
        rule = self._rule_by_id.get(m.rule_id)
        tags = (getattr(rule, "tags", None) or {}) if rule else {}
        category = tags.get("category", "")
        cat_zh = _CAT_ZH.get(category, "暴露面")
        loc_suffix, snippet = _locate(text, getattr(m, "matched_patterns", None))
        loc = path + loc_suffix
        evidence = loc
        if snippet:
            evidence += "\n命中片段：" + snippet
        impact = getattr(m, "description", None) or (
            getattr(rule, "description", "") if rule else ""
        )
        return ExposureFinding(
            id=m.rule_id,
            title=m.title,
            severity=_map_severity(m.severity),
            category=cat_zh,
            source=source,
            agent_ids=list(agent_ids),
            impact=impact,
            evidence=evidence,
            recommendation=_CAT_RECO.get(category, "请核查该来源内容并降低暴露面。"),
            plain_explanation=_CAT_PLAIN.get(category, "检测到一处可能的安全风险，建议核查。"),
            location=loc,
            locations=[loc] if loc else [],
            tags=[t for t in [category, tags.get("subcategory")] if t],
        )


_AUDIT_SEV = {
    "critical": Severity.HIGH.value,
    "high": Severity.HIGH.value,
    "error": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "moderate": Severity.MEDIUM.value,
    "warning": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.LOW.value,
    "note": Severity.LOW.value,
}


class OpenClawAuditCollector:
    """wrap `openclaw security audit --json`（只读，不用 --fix）。

    CLI 存在则真实调用并解析 checkId → ExposureFinding(source=openclaw_audit)；
    CLI 不存在或失败 → 返回空（优雅降级，不阻塞暴露面，记录到 status）。
    """

    def __init__(self):
        self.last_status = "not_run"

    def _resolve_bin(self) -> Optional[str]:
        env = os.environ.get("AGENTSEC_OPENCLAW_BIN")
        if env and os.path.isfile(env):
            return env
        return shutil.which("openclaw")

    def collect(self, agent: Agent) -> List[ExposureFinding]:
        binary = self._resolve_bin()
        if not binary:
            self.last_status = "cli_absent"
            return []
        try:
            proc = subprocess.run(
                [binary, "security", "audit", "--json"],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.last_status = f"error: {exc}"
            return []
        if proc.returncode not in (0, 1):  # 1 常表示「有发现」
            self.last_status = f"exit {proc.returncode}"
            return []
        try:
            data = json.loads(proc.stdout or "{}")
        except ValueError:
            self.last_status = "bad_json"
            return []
        self.last_status = "ok"
        return self._map(data, agent)

    def _map(self, data, agent: Agent) -> List[ExposureFinding]:
        # 兼容多种顶层形态：list / {checks|findings|results: [...]}
        items = data if isinstance(data, list) else (
            data.get("checks") or data.get("findings") or data.get("results") or []
        )
        out: List[ExposureFinding] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            check_id = str(it.get("checkId") or it.get("id") or it.get("check") or "OPENCLAW")
            sev = _AUDIT_SEV.get(str(it.get("severity", "")).lower(), Severity.MEDIUM.value)
            path = it.get("path") or it.get("file") or ""
            line = it.get("line")
            location = f"{path}:{line}" if path and line else (path or check_id)
            out.append(ExposureFinding(
                id=check_id,
                title=it.get("title") or it.get("message") or check_id,
                severity=sev,
                category="OpenClaw 基线",
                source=FindingSource.OPENCLAW_AUDIT.value,
                agent_ids=[agent.id],
                impact=it.get("description") or it.get("detail") or "",
                evidence=location,
                recommendation=it.get("remediation") or it.get("recommendation")
                or "参考 OpenClaw 官方审计建议处理该项。",
                plain_explanation="OpenClaw 官方安全审计发现的一处基线问题，建议按建议处理。",
                location=location,
                locations=[location] if location else [],
                tags=["openclaw-audit"],
            ))
        return out


class ScanTarget:
    """喂给 ATR 的可扫文件。"""

    def __init__(self, path: str, source: str, agent_ids: List[str]):
        self.path = path
        self.source = source
        self.agent_ids = agent_ids


class ExposureDetector:
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        include_experimental: bool = True,
        high_severity_only: bool = True,
    ):
        self.atr = ATREngine(
            include_experimental=include_experimental,
            high_severity_only=high_severity_only,
        )
        self.audit = OpenClawAuditCollector()

    def scan(
        self,
        agents: List[Agent],
        targets: List[ScanTarget],
        on_file_progress: Optional[Callable[[int, int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> List[ExposureFinding]:
        findings: List[ExposureFinding] = []
        total = len(targets)
        for i, t in enumerate(targets):
            if should_cancel and should_cancel():
                break
            if is_whitelisted_path(t.path):
                if on_file_progress:
                    on_file_progress(i + 1, total)
                continue
            try:
                with open(t.path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                if on_file_progress:
                    on_file_progress(i + 1, total)
                continue
            text = _preprocess_skill_text(t.path, text)
            if t.path.endswith("SKILL.md") and len(text) < _MIN_SKILL_BODY_CHARS:
                if on_file_progress:
                    on_file_progress(i + 1, total)
                continue
            findings.extend(self.atr.scan_file(t.path, text, t.source, t.agent_ids))
            if on_file_progress:
                on_file_progress(i + 1, total)
        if should_cancel and should_cancel():
            return findings
        # 仅对已发现的真实 OpenClaw Agent 跑官方 audit（需 openclaw CLI；claw3d 不算）
        for agent in agents:
            if should_cancel and should_cancel():
                break
            if agent.kind == "openclaw":
                findings.extend(self.audit.collect(agent))
        return findings

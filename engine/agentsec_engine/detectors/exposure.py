"""ExposureDetector：暴露面 / 基线 / Prompt 注入。

组成（architecture.md 附录 C）：
  - ATREngine            : pyATR（内置 459 条规则，Layer1 = regex/pattern，纯离线）
  - OpenClawAuditCollector: wrap `openclaw security audit --json`（占位）

MVP 规则子集（见 docs/engine/atr-mvp-rules.md）：
  默认启用 stable + experimental 中 severity∈{critical,high,medium}、可静态扫描目标
  （mcp/skill/both）的规则，约 266 条（排除 12 条高误报）；experimental 的 critical/high
  另要求 confidence∈{high, medium-high}，medium 严重度 experimental 全量纳入。

排除列表见 `data/atr_rules/excluded_rules.yaml`（基于本机扫描误报分析）。

pyatr 需 Python ≥ 3.10；导入失败时自动降级，由上层回落到 fixture。
"""

from __future__ import annotations

import json
import multiprocessing
import os
import queue
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

import yaml

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

# MVP 排除：对 SKILL.md 静态扫描误报率过高的宽泛规则（见 data/atr_rules/excluded_rules.yaml）
_EXCLUDED_RULES_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "atr_rules" / "excluded_rules.yaml"
)


def _load_excluded_rule_ids() -> FrozenSet[str]:
    """从 excluded_rules.yaml 加载排除列表；文件缺失时退回最小集。"""
    fallback = frozenset({"ATR-2026-00001", "ATR-2026-00030"})
    try:
        with open(_EXCLUDED_RULES_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return fallback
    rules = data.get("rules")
    if not isinstance(rules, list):
        return fallback
    ids = {r["id"] for r in rules if isinstance(r, dict) and r.get("id")}
    return frozenset(ids) if ids else fallback


_EXCLUDED_RULE_IDS = _load_excluded_rule_ids()

# 单文件 ATR 最长执行时间。第三方规则使用 Python re，必须放到可终止的子进程中，
# 否则灾难性回溯会占住整个扫描线程且无法取消。
_ATR_FILE_TIMEOUT_SECONDS = 12.0

# SKILL.md YAML frontmatter 剥离（--- ... ---），避免元数据 boilerplate 误报
_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n?", re.DOTALL)
_MIN_SKILL_BODY_CHARS = 32

_DEFENSIVE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:security guidance|architecture note|example(?:s)? to block|"
    r"detect(?:ion)?|prevent|mitigat|defend|never|do not|don't|must not|avoid)\b"
)
_OVERRIDE_INTENT_RE = re.compile(
    r"(?i)\b(?:ignore|disregard|override|replace|forget)\b.{0,100}"
    r"\b(?:previous|prior|system|developer|tool)\b"
)
_DISCLOSURE_INTENT_RE = re.compile(
    r"(?i)\b(?:reveal|show|print|output|extract|leak|repeat)\b.{0,100}\bsystem prompt\b"
)
_CREDENTIAL_TARGET_RE = re.compile(
    r"(?i)(?:~/)?\.(?:ssh|aws|env)|credentials?|keychain|id_rsa|secret manager"
)
_THEFT_INTENT_RE = re.compile(
    r"(?i)\b(?:read|copy|steal|collect|harvest|exfiltrat|upload|send|post)\b"
)
_EXFIL_INTENT_RE = re.compile(
    r"(?i)\b(?:exfiltrat|upload|send|post|transmit|webhook|attacker)\b"
)
_REMOTE_EXEC_RE = re.compile(
    r"""(?isx)
    (?:
      \b(?:curl|wget)\b[^\n]{0,240}https?://
      (?!127\.0\.0\.1|localhost|\[?::1\]?)[^\s|;]+[^\n]{0,320}
      (?:
        \|\s*(?:/[^\s|;]+/)?(?:ba|z|da)?sh\b
        |&&\s*(?:/[^\s|;]+/)?(?:ba|z|da)?sh\b
        |\b(?:chmod\s+\+x|execute)\b[^\n]{0,160}(?:/tmp/|\./)
      )
      |
      \bpython(?:3)?\b
      (?=[^\n]{0,640}\bexec\s*\()
      (?=[^\n]{0,640}\b(?:urlopen|requests?\.get)\b)
      [^\n]{0,640}https?://
      (?!127\.0\.0\.1|localhost|\[?::1\]?)[^\s'"]+
    )
    """
)
_TOOL_SHADOW_RE = re.compile(
    r"(?is)\bIMPORTANT\b.{0,120}(?:"
    r"\bbefore\s+(?:using|calling)\s+(?:any\s+)?other\s+tool\b|"
    r"\bignore\b.{0,80}\b(?:other|its|their|tool)\b.{0,40}\binstructions?\b)"
)
_CHAR_ENCODING_RE = re.compile(r"(?:\\[A-Za-z0-9]){8,}")
_PERSONA_BYPASS_RE = re.compile(
    r"(?i)\b(?:jailbreak|uncensored|DAN|evil persona|bypass safety|ignore safety|disable safety)\b"
)
_MULTI_TURN_INJECTION_RE = re.compile(
    r"(?i)\b(?:in (?:the )?(?:next|future) (?:message|turn)|remember this instruction|"
    r"when I (?:later )?say|defer(?:red)? instruction)\b"
)
_VARIABLE_INJECTION_RE = re.compile(
    r"(?is)\b(?:user input|prompt|payload)\b.{0,180}"
    r"\b(?:ignore|override|replace|system prompt|instructions?)\b"
)
_BACKUP_HARVEST_RE = re.compile(
    r"(?is)\b(?:backup|restore)\b.{0,180}\b(?:credential|token|api key|secret|password)\b"
    r".{0,180}\b(?:send|upload|post|webhook|remote)\b"
)
_PIGGYBACK_EXFIL_RE = re.compile(
    r"(?is)\b(?:by the way|also|one more thing|casually)\b.{0,180}"
    r"\b(?:secret|token|credential|api key)\b.{0,180}\b(?:send|upload|post|webhook)\b"
)


def _matched_context(text: str, patterns, radius: int = 320) -> str:
    for pattern in patterns or []:
        try:
            match = re.search(pattern, text)
        except re.error:
            continue
        if match:
            return text[max(0, match.start() - radius): min(len(text), match.end() + radius)]
    return text if len(text) <= radius * 2 else ""


def _suppress_noisy_static_match(rule_id: str, text: str, patterns, source: str) -> bool:
    """为已知宽泛规则增加意图组合条件，避免文档词汇本身触发高危。"""
    context = _matched_context(text, patterns)
    defensive = bool(_DEFENSIVE_CONTEXT_RE.search(context))
    if rule_id == "ATR-2026-00120":
        return "ascii-guard-ignore" in context.lower()
    if rule_id == "ATR-2026-00213":
        return defensive or not _OVERRIDE_INTENT_RE.search(context)
    if rule_id == "ATR-2026-00514":
        return defensive or not _DISCLOSURE_INTENT_RE.search(context)
    if rule_id == "ATR-2026-00113":
        return not (_CREDENTIAL_TARGET_RE.search(context) and _THEFT_INTENT_RE.search(context))
    if rule_id == "ATR-2026-00115":
        return not _EXFIL_INTENT_RE.search(context)
    if rule_id == "ATR-2026-00161":
        return not _TOOL_SHADOW_RE.search(context)
    if rule_id == "ATR-2026-00121":
        return not _REMOTE_EXEC_RE.search(context)
    if rule_id == "ATR-2026-00454":
        return not _CHAR_ENCODING_RE.search(context)
    if rule_id == "ATR-2026-00245":
        return not _PERSONA_BYPASS_RE.search(context)
    if rule_id == "ATR-2026-00446":
        return not _VARIABLE_INJECTION_RE.search(context)
    if rule_id == "ATR-2026-00217":
        return not _BACKUP_HARVEST_RE.search(context)
    if rule_id == "ATR-2026-00005":
        return not _MULTI_TURN_INJECTION_RE.search(context)
    if rule_id == "ATR-2026-00142":
        return not _PIGGYBACK_EXFIL_RE.search(context)
    if rule_id in {"ATR-2026-00528", "ATR-2026-00419"} and source == FindingSource.SKILL.value:
        return True
    if rule_id == "ATR-2026-00524":
        return not re.search(r"(?i)ANTHROPIC_(?:API_KEY|AUTH_TOKEN)", text)
    return False

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
    """屏蔽 SKILL.md YAML frontmatter，同时保留原始换行以保证行号准确。"""
    if not path.endswith("SKILL.md"):
        return text
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return text
    masked = "".join("\n" if ch == "\n" else " " for ch in match.group(0))
    return masked + text[match.end():]


def _allowed_targets_for_source(source: str) -> Set[str]:
    if source == FindingSource.SKILL.value:
        return {"skill", "both"}
    if source == FindingSource.MCP.value:
        return {"mcp", "both"}
    # Agent 配置、规则和知识库没有对应的 ATR scan_target，只运行明确标记为 both 的规则。
    return {"both"}


def _rule_matches_source(rule, source: str) -> bool:
    tags = getattr(rule, "tags", None) or {}
    return tags.get("scan_target") in _allowed_targets_for_source(source)


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
        self._subset_rules = [
            r for r in self._engine.rules if r.id in self._subset_ids
        ]
        # 性能：原地裁剪规则列表，evaluate 只跑子集（459 → ~266，详见 atr-mvp-rules.md）。
        try:
            self._engine._rules[:] = self._subset_rules
        except Exception:  # noqa: BLE001 - 裁剪失败则退回全量+结果过滤
            pass

    @property
    def subset_size(self) -> int:
        return len(self._subset_ids)

    def scan_file(
        self,
        path: str,
        text: str,
        source: str,
        agent_ids: List[str],
        *,
        include_supplemental: bool = True,
    ) -> List[ExposureFinding]:
        if not self.available or not text:
            return []
        allowed_ids = {
            r.id for r in self._subset_rules if _rule_matches_source(r, source)
        }
        try:
            self._engine._rules[:] = [
                r for r in self._subset_rules if r.id in allowed_ids
            ]
        except Exception:  # noqa: BLE001
            pass
        event = _AgentEvent(content=text, fields={"content": text})
        out: List[ExposureFinding] = []
        seen = set()
        for m in self._engine.evaluate(event):
            if m.rule_id not in allowed_ids or m.rule_id in seen:
                continue
            if _suppress_noisy_static_match(
                m.rule_id, text, getattr(m, "matched_patterns", None), source
            ):
                continue
            seen.add(m.rule_id)
            out.append(self._to_finding(m, path, text, source, agent_ids))
        if include_supplemental:
            out.extend(self.supplemental_findings(path, text, source, agent_ids, seen))
        return out

    def supplemental_findings(self, path, text, source, agent_ids, seen=None):
        seen = seen or set()
        out: List[ExposureFinding] = []
        checks = [
            (
                "AGENTSEC-STATIC-REMOTE-EXEC",
                "ATR-2026-00121",
                _REMOTE_EXEC_RE,
                "远程脚本下载并执行",
                "Skill 风险",
                "检测到从非本机地址下载内容并直接交给 Shell 执行。",
                "不要直接执行远程脚本；固定版本与校验和，并在隔离环境中审查后运行。",
                "远程下载内容未经审查就执行，可能导致任意代码运行。",
                "remote-exec",
            ),
            (
                "AGENTSEC-STATIC-TOOL-SHADOWING",
                "ATR-2026-00161",
                _TOOL_SHADOW_RE,
                "工具优先级劫持指令",
                "工具投毒",
                "检测到要求忽略其他工具指令并强制优先调用当前工具的内容。",
                "移除跨工具优先级指令，并核查该工具的来源与最小权限。",
                "工具描述试图改变其他工具的调用顺序，可能劫持 Agent 行为。",
                "tool-shadowing",
            ),
        ]
        for fid, equivalent_id, pattern, title, category, impact, recommendation, plain, tag in checks:
            if fid in seen or equivalent_id in seen:
                continue
            m = pattern.search(text)
            if not m:
                continue
            line = text.count("\n", 0, m.start()) + 1
            loc = f"{path}:{line}"
            snippet = m.group(0).replace("\n", " ").strip()[:160]
            out.append(ExposureFinding(
                id=fid,
                title=title,
                severity=Severity.HIGH.value,
                category=category,
                source=source,
                agent_ids=list(agent_ids),
                impact=impact,
                evidence=f"{loc}\n命中片段：{snippet}",
                recommendation=recommendation,
                plain_explanation=plain,
                location=loc,
                locations=[loc],
                tags=[tag],
            ))
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
        from ..config import get_agent_bin

        configured = get_agent_bin("openclaw")
        if configured and os.path.isfile(configured):
            return configured
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
            if check_id.startswith("summary.") or str(it.get("type", "")).lower() == "summary":
                continue
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


def _atr_worker_main(
    requests,
    responses,
    include_experimental: bool,
    high_severity_only: bool,
) -> None:
    """独立 ATR worker；父进程可在单条规则卡死时安全终止。"""
    engine = ATREngine(
        include_experimental=include_experimental,
        high_severity_only=high_severity_only,
    )
    while True:
        job = requests.get()
        if job is None:
            return
        job_id, path, text, source, agent_ids = job
        try:
            findings = engine.scan_file(
                path,
                text,
                source,
                agent_ids,
                include_supplemental=False,
            )
            responses.put((job_id, "ok", [f.to_dict() for f in findings]))
        except BaseException as exc:  # noqa: BLE001 - 错误需回传父进程并隔离
            responses.put((job_id, "error", f"{type(exc).__name__}: {exc}"))


class _ATRProcessWorker:
    """单 worker 复用规则加载；超时或取消时直接终止进程。"""

    def __init__(self, include_experimental: bool, high_severity_only: bool):
        self.include_experimental = include_experimental
        self.high_severity_only = high_severity_only
        self._ctx = multiprocessing.get_context("spawn")
        self._process = None
        self._requests = None
        self._responses = None
        self._job_id = 0

    def _start(self) -> None:
        self._requests = self._ctx.Queue()
        self._responses = self._ctx.Queue()
        self._process = self._ctx.Process(
            target=_atr_worker_main,
            args=(
                self._requests,
                self._responses,
                self.include_experimental,
                self.high_severity_only,
            ),
            daemon=True,
        )
        self._process.start()

    def _terminate(self) -> None:
        if self._process is not None and self._process.is_alive():
            self._process.terminate()
        if self._process is not None:
            self._process.join(timeout=2)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=1)
        for q in (self._requests, self._responses):
            if q is not None:
                q.close()
        self._process = None
        self._requests = None
        self._responses = None

    def scan(
        self,
        target: ScanTarget,
        text: str,
        *,
        timeout: float,
        should_cancel: Optional[Callable[[], bool]],
    ) -> Tuple[str, List[ExposureFinding], str]:
        if self._process is None or not self._process.is_alive():
            self._terminate()
            self._start()
        self._job_id += 1
        job_id = self._job_id
        self._requests.put(
            (job_id, target.path, text, target.source, target.agent_ids)
        )
        deadline = time.monotonic() + timeout
        while True:
            if should_cancel and should_cancel():
                self._terminate()
                return "cancelled", [], ""
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate()
                return "timeout", [], ""
            if self._process is None or not self._process.is_alive():
                self._terminate()
                return "error", [], "ATR worker exited unexpectedly"
            try:
                result_id, status, payload = self._responses.get(
                    timeout=min(0.1, remaining)
                )
            except queue.Empty:
                continue
            if result_id != job_id:
                continue
            if status != "ok":
                return "error", [], str(payload)
            return "ok", [ExposureFinding(**item) for item in payload], ""

    def close(self) -> None:
        if self._process is not None and self._process.is_alive():
            try:
                self._requests.put(None)
                self._process.join(timeout=2)
            except (OSError, ValueError):
                pass
        self._terminate()


class ExposureDetector:
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        include_experimental: bool = True,
        high_severity_only: bool = True,
    ):
        self.include_experimental = include_experimental
        self.high_severity_only = high_severity_only
        self.atr = ATREngine(
            include_experimental=include_experimental,
            high_severity_only=high_severity_only,
        )
        self.audit = OpenClawAuditCollector()
        self.last_diagnostics = {
            "status": "ok" if self.atr.available else "unavailable",
            "timed_out_paths": [],
            "read_error_paths": [],
            "worker_errors": [],
        }

    def scan(
        self,
        agents: List[Agent],
        targets: List[ScanTarget],
        on_file_progress: Optional[Callable[[int, int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
        run_openclaw_audit: bool = True,
    ) -> List[ExposureFinding]:
        findings: List[ExposureFinding] = []
        self.last_diagnostics = {
            "status": "ok" if self.atr.available else "unavailable",
            "timed_out_paths": [],
            "read_error_paths": [],
            "worker_errors": [],
        }
        total = len(targets)
        worker = (
            _ATRProcessWorker(self.include_experimental, self.high_severity_only)
            if self.atr.available
            else None
        )
        try:
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
                    self.last_diagnostics["read_error_paths"].append(t.path)
                    if on_file_progress:
                        on_file_progress(i + 1, total)
                    continue
                text = _preprocess_skill_text(t.path, text)
                if (
                    t.path.endswith("SKILL.md")
                    and len(text.strip()) < _MIN_SKILL_BODY_CHARS
                ):
                    if on_file_progress:
                        on_file_progress(i + 1, total)
                    continue

                # 自有高价值规则先在父进程完整扫描，不受第三方 ATR 超时影响。
                supplemental = self.atr.supplemental_findings(
                    t.path, text, t.source, t.agent_ids
                )
                if worker is not None:
                    status, atr_findings, detail = worker.scan(
                        t,
                        text,
                        timeout=_ATR_FILE_TIMEOUT_SECONDS,
                        should_cancel=should_cancel,
                    )
                    if status == "ok":
                        atr_ids = {f.id for f in atr_findings}
                        equivalent = {
                            "AGENTSEC-STATIC-REMOTE-EXEC": "ATR-2026-00121",
                            "AGENTSEC-STATIC-TOOL-SHADOWING": "ATR-2026-00161",
                        }
                        supplemental = [
                            f
                            for f in supplemental
                            if equivalent.get(f.id) not in atr_ids
                        ]
                        existing = {
                            (f.id, f.location) for f in findings
                        }
                        findings.extend(
                            f
                            for f in atr_findings
                            if (f.id, f.location) not in existing
                        )
                    elif status == "timeout":
                        self.last_diagnostics["timed_out_paths"].append(t.path)
                    elif status == "error":
                        self.last_diagnostics["worker_errors"].append(
                            {"path": t.path, "error": detail}
                        )
                findings.extend(supplemental)
                if on_file_progress:
                    on_file_progress(i + 1, total)
        finally:
            if worker is not None:
                worker.close()

        if self.last_diagnostics["status"] != "unavailable" and (
            self.last_diagnostics["timed_out_paths"]
            or self.last_diagnostics["read_error_paths"]
            or self.last_diagnostics["worker_errors"]
        ):
            self.last_diagnostics["status"] = "partial"
        if should_cancel and should_cancel():
            return findings
        # 仅对已发现的真实 OpenClaw Agent 跑官方 audit（需 openclaw CLI；claw3d 不算）
        if run_openclaw_audit:
            for agent in agents:
                if should_cancel and should_cancel():
                    break
                if agent.kind == "openclaw":
                    findings.extend(self.audit.collect(agent))
        return findings

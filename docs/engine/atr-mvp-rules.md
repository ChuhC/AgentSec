# agentSec · ATR 暴露面规则 — MVP 方案

> 状态：已实现（pyatr 0.2.6 接入完成）  
> 依据：[`architecture.md`](../architecture/architecture.md) 附录 B/C、[`requirements.md`](../requirements/requirements.md)

> **实测更新（接入后）**：`pyatr` 包**内置 459 条规则**（Layer 1 = regex/pattern），
> 而非外挂 `rules/` 目录；其中 `status=stable` 共 **26 条**。bundled 覆盖 **9 个类别**
> （无 `model-security`，`data-poisoning` 仅 4 条）。MVP 子集据此调整为下方实测口径。

---

## 1. 总策略

| 项 | 决策 |
|----|------|
| **暴露面引擎** | [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) via **pyatr 0.2.6**（`load_bundled_rules()`） |
| **规则交付** | pyatr 包**内置**规则，随引擎打包；扫描时 **纯离线**、无 LLM |
| **运行时** | pyatr 需 **Python ≥ 3.10**；引擎跑在 `engine/.venv`（3.11） |
| **CVE** | **不在 ATR**；由 `CVEDetector` + OSV 单独处理 |
| **OpenClaw 补充** | `openclaw security audit --json`（占位，待接入） |
| **MVP 规则子集** | `status=stable` 且 `tags.scan_target ∈ {mcp, skill, both}` ⇒ **18 条**（静态可扫目标）|

### 实测 API（pyatr 0.2.6）

```python
from pyatr import ATREngine, AgentEvent
engine = ATREngine(); engine.load_bundled_rules()        # 459 条
# 静态文件扫描：内容填入所有字段 + 按子集 rule_id 过滤命中
ev = AgentEvent(content=text, fields={f: text for f in ALL_FIELDS})
matches = engine.evaluate(ev)   # → ATRMatch(rule_id, title, severity, confidence, matched_patterns, tags)
```

- 合法 `event_type`：`llm_input / llm_output / tool_call / tool_response / multi_agent_message`（另 `content` 字段直接可匹配）
- `engine.rules` 只读 ⇒ 子集通过**过滤 matches 的 rule_id**实现（而非替换规则集）
- 规则分类信息在 `rule.tags`：`category / subcategory / scan_target / confidence`

---

## 2. ATR 十大类 → agentSec MVP 启用策略

每类 MVP 目标 **4–6 条** pattern 规则（实施时从 ATR 仓库按 tag/category 挑选 `status: stable`）。

| # | ATR 类别 | MVP 目标条数 | 扫什么 | agentSec UI 归类 |
|---|----------|-------------|--------|------------------|
| 1 | **Prompt Injection** | 5–6 | SKILL.md、rules、MCP 描述中的 override/jailbreak | 暴露面 · Prompt 注入 |
| 2 | **Agent Manipulation** | 4–5 | 目标劫持、DAN 类、eval/lambda 危险模式（文本） | 暴露面 · 基线 |
| 3 | **Skill Compromise** | 4–5 | typosquat、远程拉脚本、rug pull 信号 | 组件 · Skill |
| 4 | **Context Exfiltration** | 5–6 | 硬编码 key、env 外泄、外传 URL/webhook | 暴露面 · 凭证/外泄 |
| 5 | **Tool Poisoning** | 5–6 | MCP tool 描述隐藏指令、Unicode 欺骗、参数注入 | 暴露面 · MCP |
| 6 | **Privilege Escalation** | 4–5 | 过宽权限声明、shell/sudo、敏感路径 | 权限 / 暴露面 |
| 7 | **Model Abuse** | 2–3 | 明显 malwaregen/EICAR 类（Skill 脚本文本） | 暴露面 · 低优先 |
| 8 | **Excessive Autonomy** | 3–4 | 无边界自主、金融/批量操作描述 | 暴露面 · 基线 |
| 9 | **Model Security** | 1–2 | 系统 prompt 提取类（静态） | 暴露面 |
| 10 | **Data Poisoning** | 2–3 | RAG/记忆持久化 override（SKILL/KB 文本） | 暴露面 · 知识库 |

**合计：约 45–60 条**（可随首轮 Hermes/OpenClaw 实测微调 ±10）。

### 明确不启用（MVP）

| 类型 | 原因 |
|------|------|
| `detection_tier: behavioral` | 需运行时指标/日志 |
| `detection_tier: protocol` | 需多步会话/事件流 |
| 依赖 **LLM I/O 实时流** 的规则 | 桌面静态扫无数据 |
| 与 **OpenClaw audit checkId** 完全重复的项 | 避免双报；保留 OpenClaw 侧 |

---

## 3. Discovery → ATR 输入映射

| Discovery 产出 | ATR `event_type` / 扫法 | 示例路径 |
|----------------|-------------------------|----------|
| Skill 目录 / `SKILL.md` | `skill_md` / 目录 scan | `~/.*/skills/**`, agent skill 根 |
| MCP 注册 JSON | `mcp_config` | `mcp.json`, `claude_desktop_config` 等价物 |
| Agent 主配置 | `agent_config` | OpenClaw `openclaw.json`, Hermes 配置 |
| 依赖 lockfile | **不送 ATR** | → `CVEDetector` only |

---

## 4. Reporter 映射（固定）

| ATR 字段 | agentSec `ExposureFinding` |
|----------|----------------------------|
| `rule.id` (`ATR-YYYY-NNNNN`) | `id`（保留，便于追溯） |
| `severity` | `critical/high`→高，`medium`→中，`low/info`→低 |
| `references.owasp_agentic` | `tags[]` |
| 文件路径 + 行 | `location`；`source` = skill \| mcp \| agent_config \| openclaw_audit |
| `message` / `response.message_template` | `title` + `impact`（Reporter 脱敏后落盘） |

**去重键：** `(source, check_id, path, line)`

---

## 5. 打包与许可

| 项 | 说明 |
|----|------|
| 依赖 | `pyatr`（MIT） |
| 规则文件 | 从 upstream `rules/` **拷贝子集**到 `agentsec/engine/data/atr_rules/` |
| 许可 | `THIRD_PARTY_NOTICES` 注明 ATR + MIT；保留各规则 YAML 内 author/date |
| 更新 | MVP 随 agentSec 版本发布；vNext 可选「规则包增量更新」 |

---

## 6. 实施进度

- [x] **ATREngine 封装** `engine/agentsec_engine/detectors/exposure.py`：`load_bundled_rules` →
      MVP 子集过滤（18 条）→ `scan_file` 静态评估 → 映射为 `ExposureFinding`
- [x] **子集口径**：`stable` + `scan_target∈{mcp,skill,both}`；可选 `include_experimental=True` 扩展
- [x] **样例驱动**：`data/samples/`（Hermes/OpenClaw 的 mcp.json + SKILL.md）让真实 ATR 跑出
      `ATR-2026-NNNNN` 命中（含真实行号定位）
- [x] **映射**：severity（critical/high→高，medium→中，其余→低）、category→中文、
      `matched_patterns` 回溯原文片段+行号作证据、按类别生成中文 `recommendation`/通俗说明
- [ ] **真实 Adapter 路径**：`atr_targets()` 现返回样例文件，待替换为本机实际 skill/mcp/agent 配置
- [ ] **OpenClawAuditCollector**：接入 `openclaw security audit --json`
- [ ] 视需要纳入精选 `experimental` 规则以补齐 medium/low 与更多类别

---

## 7. 成功标准（MVP）

- [ ] 离线扫描 Hermes + OpenClaw 样本能产出暴露面 Finding  
- [ ] 10 类均有至少 1 条命中能力（fixture 或 dogfood 环境）  
- [ ] 无 CVE/LLM 出站（除 CVEDetector 的 OSV）  
- [ ] UI 双 KPI：暴露面与 CVE 分开；Finding 可定位到 Step7 来源 Tab  

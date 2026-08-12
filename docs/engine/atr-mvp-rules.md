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
| **运行时** | pyatr 需 **Python ≥ 3.10**；单文件在可终止 worker 进程运行，默认硬超时 12s |
| **CVE** | **不在 ATR**；由 `CVEDetector` + OSV 单独处理 |
| **OpenClaw 补充** | 已接入 `openclaw security audit --json`；仅全机扫描运行，自定义范围禁用 |
| **MVP 规则子集（默认）** | `stable`+`experimental` 且 `severity∈{critical,high,medium}`、`scan_target∈{mcp,skill,both}`；experimental 的 critical/high 另需 `confidence∈{high,medium-high}`，medium 全量纳入 ⇒ **约 266 条**（排除 12 条高误报，见 §2.1）|
| **Legacy 最小子集** | `include_experimental=False` 且 `high_severity_only=False` ⇒ **约 16 条** stable |

### 2.1 MVP 排除规则（静态 SKILL 扫描）

排除列表维护在 **`engine/agentsec_engine/data/atr_rules/excluded_rules.yaml`**，
由 `ExposureDetector` / `ATREngine` 启动时加载（`_load_excluded_rule_ids()`）。

以下规则对 SKILL.md 静态 regex 扫描误报率过高，已从默认子集剔除：

| rule_id | 名称 | 排除原因 |
|---------|------|----------|
| `ATR-2026-00001` | Indirect Prompt Injection via External Content | 正常 skill 常描述外部输入/引用 |
| `ATR-2026-00002` | Indirect Prompt Injection via External Content | 与 00001 同类，文档中极常见 |
| `ATR-2026-00004` | System Prompt Override Attempt | 文档出现 system prompt 术语即命中 |
| `ATR-2026-00030` | Cross-Agent Attack Detection | 多 agent 协作文档触发面过宽 |
| `ATR-2026-00110` | Remote Code Execution via eval() | code-review skill 中 grep 检测 eval 示例 |
| `ATR-2026-00111` | Shell Metacharacter Injection | bash/CLI 示例（反引号、管道）大面积误报 |
| `ATR-2026-00118` | Human Approval Fatigue Exploitation | 英文 normal、配置项关键字误命中 |
| `ATR-2026-00223` | Reverse Shell Dropper (WhatsApp) | localhost 调试 curl，非 C2 |
| `ATR-2026-00225` | Hardcoded Suspicious IP | 0.0.0.0 等绑定地址出现在错误说明 |
| `ATR-2026-00398` | Unsafe Model Artifact Load | 与 00110 同类 grep eval 示例 |
| `ATR-2026-00424` | NL System Prompt Leak | 「Do not expose…」否定句安全规范 |
| `ATR-2026-00510` | Delayed Tool Invocation | CLI 帮助 run ID 等子串误命中 |

新增排除项时：编辑 `excluded_rules.yaml` 并同步更新本表；重启引擎后重新扫描生效。

扫描前对 `SKILL.md` 的 YAML frontmatter 做**等长遮罩**（不删除），因此正文命中的原始
行号保持准确；正文过短（&lt;32 字符）则跳过。文件内容不再按 65,536 字符截断。

### 2.2 准确率回归语料

正负样本维护在 **`engine/tests/fixtures/atr_accuracy.json`**，由
`engine/tests/test_exposure_accuracy.py` 参数化执行。恶意样本必须命中其
`expected_any_of` 中至少一个预期检测器；良性样本必须零告警，防止用另一个误报“碰巧”
满足恶意样本测试。

当前语料覆盖 Prompt override、凭证外传、远程脚本直执行、跨工具优先级劫持，以及
安全防御文档、环境变量调试、MCP/密钥文档、本机健康检查、编码/线协议、XML 代码、
替代 API endpoint 等常见良性内容。每次处理线上或 dogfood 误报/漏报时，必须先把最小
复现加入该语料，再调整规则组合条件。

对 pyATR 中已知过宽但仍有有效信号的规则，不直接按单关键词采信，而是在
`ExposureDetector` 中增加局部上下文组合条件；远程下载直执行和明确的跨工具劫持由
AgentSec 静态补充检测器兜底。

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
- 规则按输入来源二次过滤：Skill 仅接收 `skill|both`，MCP 仅接收 `mcp|both`，
  其他 Agent 配置仅接收 `both`，防止跨目标规则造成误报。

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
| Skill 目录 / `SKILL.md` | 所有静态字段 + 仅 `scan_target=skill|both` | `~/.*/skills/**`, agent skill 根 |
| MCP 注册 JSON/YAML/TOML | 所有静态字段 + 仅 `scan_target=mcp|both` | 各 Agent MCP 配置 |
| Agent 主配置 | 所有静态字段 + 仅 `scan_target=both` | OpenClaw、Hermes、Claude、Codex 配置 |
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

**去重键：** `(source, rule_id)` — Reporter 聚合同规则多文件命中；`locations[]` 保留全部路径，`evidence` 合并前 3 条。

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
      默认子集过滤（~266 条，含 medium 全量，排除 12 条高误报）→ `scan_file` 静态评估 → 映射为 `ExposureFinding`
- [x] **子集口径（默认）**：`stable|experimental` + `severity∈{critical,high,medium}` + 静态 `scan_target`
      − `excluded_rules.yaml`；experimental 的 critical/high 需 `confidence∈{high,medium-high}`
- [x] **Legacy 最小子集**：`ExposureDetector(include_experimental=False, high_severity_only=False)` → ~16 条
- [x] **准确率语料**：`tests/fixtures/atr_accuracy.json` 同时维护恶意与良性样本；恶意样本
      校验预期 detector ID，良性样本要求零告警
- [x] **映射**：severity（critical/high→高，medium→中，其余→低）、category→中文、
      `matched_patterns` 回溯原文片段+行号作证据、按类别生成中文 `recommendation`/通俗说明
- [x] **真实 Adapter 路径**：各 Adapter 的 `atr_targets()` 返回本机 skill/mcp/agent 配置
- [x] **OpenClawAuditCollector**：接入 `openclaw security audit --json`，过滤 summary 记录
- [x] **隔离与完整性**：ATR 使用可终止 worker；单文件超时/读取失败写入 diagnostics，
      整体快照标记 `partial`，UI 不显示虚假的 100 分
- [ ] 视需要纳入 `low/info` 严重度或 `confidence=medium` 的 experimental 规则

---

## 7. 成功标准（MVP）

- [ ] 离线扫描 Hermes + OpenClaw 样本能产出暴露面 Finding  
- [ ] 10 类均有至少 1 条命中能力（fixture 或 dogfood 环境）  
- [ ] 无 CVE/LLM 出站（除 CVEDetector 的 OSV）  
- [ ] UI 双 KPI：暴露面与 CVE 分开；Finding 可定位到 Step7 来源 Tab  

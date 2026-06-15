# agentSec · ATR 暴露面规则 — MVP 方案

> 状态：已确认  
> 依据：[`architecture.md`](../architecture/architecture.md) 附录 B/C、[`requirements.md`](../requirements/requirements.md)

---

## 1. 总策略

| 项 | 决策 |
|----|------|
| **暴露面引擎** | [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) via **pyATR** |
| **规则交付** | `rules/` **子集内置**于 dmg；扫描时 **纯离线** |
| **LLM** | 不使用 |
| **CVE** | **不在 ATR**；由 `CVEDetector` + OSV 单独处理 |
| **OpenClaw 补充** | `openclaw security audit --json`（专有 checkId） |
| **MVP 规则规模** | 从 ATR 全库（~651 条 / 10 类）筛 **~45–60 条** `pattern` + `stable` |

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

## 6. 实施顺序（建议）

1. **Adapter 调研表**：Hermes/OpenClaw 配置/skill/MCP 路径清单  
2. **规则子集 v1**：按上表 10 类从 ATR 仓库选出 ~50 条，写入 `atr_rules/` + 清单 `atr_rules/MANIFEST.yaml`  
3. **ATREngine 封装**：`ExposureDetector.scan(paths) → list[ExposureFinding]`  
4. **OpenClawAuditWrapper** 并行，Reporter 合并  
5. **fixture 测试**：每类至少 1 个 positive + 1 个 negative 样本  

---

## 7. 成功标准（MVP）

- [ ] 离线扫描 Hermes + OpenClaw 样本能产出暴露面 Finding  
- [ ] 10 类均有至少 1 条命中能力（fixture 或 dogfood 环境）  
- [ ] 无 CVE/LLM 出站（除 CVEDetector 的 OSV）  
- [ ] UI 双 KPI：暴露面与 CVE 分开；Finding 可定位到 Step7 来源 Tab  

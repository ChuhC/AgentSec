# agentSec macOS 桌面 UI — 分步设计稿（定稿）

> PRD：[`../../prd-sketch.md`](../../prd-sketch.md)  
> 设计规范：[`DESIGN-SHELL.md`](./DESIGN-SHELL.md)

## 安全扫描

| 步骤 | 文件 | 场景 |
|------|------|------|
| 1 | [step1-home-idle.png](./step1-home-idle.png) | 首页 |
| 1b | [step1-scan-path-modal.png](./step1-scan-path-modal.png) | 扫描路径弹窗 |
| 2 | [step2-home-scanning.png](./step2-home-scanning.png) | 扫描中 |
| 3 | [step3-results-cards-v3.png](./step3-results-cards-v3.png) | 结果概览（左上综合评分 + 威胁/漏洞分卡） |
| 3（v2） | [step3-results-cards-v2.png](./step3-results-cards-v2.png) | 历史参考 |
| 4a | [step4-security-issues-list.png](./step4-security-issues-list.png) | 威胁管理（全机）：列表 + 右侧详情 |
| 4b | [step4-component-issues-list.png](./step4-component-issues-list.png) | 组件漏洞：列表 + 右侧 CVE |

## 资产管理（Step6 → Step7）

| 步骤 | 文件 | 场景 |
|------|------|------|
| 6 | [step6-agent-list.png](./step6-agent-list.png) | **Agent 列表入口** |
| 7a | [step7-agent-overview.png](./step7-agent-overview.png) | Agent 工作台 · **概览**（四宫格均衡；雷达角标入口） |
| 7c | [step7-permission-modal.png](./step7-permission-modal.png) | **权限详情弹窗**（概览内交互态） |
| 7b | [step7-agent-mcp-tab.png](./step7-agent-mcp-tab.png) | Agent 工作台 · **资产管理** · MCP 子 Tab（示例） |
| 7d | [step7-agent-threat-tab.png](./step7-agent-threat-tab.png) | Agent 工作台 · **威胁管理**（左右分栏，无顶部概览卡） |
| 7e | [step7-agent-vuln-tab.png](./step7-agent-vuln-tab.png) | Agent 工作台 · **漏洞管理**（全宽列表，无顶部概览卡） |

```text
侧栏 资产管理 / Step3 资产卡 → Step6 → 点击 Agent → Step7 概览
Tab：概览 | 资产管理 | 威胁管理 | 漏洞管理
  · 威胁管理 = 该 Agent 的暴露面/安全规则事件（exposure_findings），左右分栏
  · 漏洞管理 = 该 Agent 的组件 CVE（cve_findings），全宽表格
雷达隐蔽入口（角标/点图）→ 权限详情弹窗（非独立页、非固定跳 MCP）
```

## 设置

| 步骤 | 文件 | 场景 |
|------|------|------|
| 9 | [step9-settings.png](./step9-settings.png) | 内部设置页 |

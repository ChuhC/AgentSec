# agentSec macOS 桌面 UI — 分步设计稿（定稿）

> PRD：[`../../prd-sketch.md`](../../prd-sketch.md)  
> 设计规范：[`DESIGN-SHELL.md`](./DESIGN-SHELL.md)

## 安全扫描

| 步骤 | 文件 | 场景 |
|------|------|------|
| 1 | [step1-home-idle.png](./step1-home-idle.png) | 首页 |
| 1b | [step1-scan-path-modal.png](./step1-scan-path-modal.png) | 扫描路径弹窗 |
| 2 | [step2-home-scanning.png](./step2-home-scanning.png) | 扫描中 |
| 3 | [step3-results-cards.png](./step3-results-cards.png) | 结果概览 + Top3 |
| 4a | [step4-security-issues-list.png](./step4-security-issues-list.png) | 暴露面：列表 + 右侧详情 |
| 4b | [step4-component-issues-list.png](./step4-component-issues-list.png) | 组件漏洞：列表 + 右侧 CVE |

## 资产管理（Step6 → Step7）

| 步骤 | 文件 | 场景 |
|------|------|------|
| 6 | [step6-agent-list.png](./step6-agent-list.png) | **Agent 列表入口** |
| 7a | [step7-agent-overview.png](./step7-agent-overview.png) | Agent 工作台 · **概览**（四宫格均衡；雷达角标入口） |
| 7c | [step7-permission-modal.png](./step7-permission-modal.png) | **权限详情弹窗**（概览内交互态） |
| 7b | [step7-agent-mcp-tab.png](./step7-agent-mcp-tab.png) | Agent 工作台 · **MCP Tab** |

```text
侧栏 资产管理 / Step3 资产卡 → Step6 → 点击 Agent → Step7 概览
雷达隐蔽入口（角标/点图）→ 权限详情弹窗（非独立页、非固定跳 MCP）
```

## 设置

| 步骤 | 文件 | 场景 |
|------|------|------|
| 9 | [step9-settings.png](./step9-settings.png) | 内部设置页 |

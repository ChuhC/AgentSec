# AgentSec

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/ChuhC/AgentSec/releases)

**Languages / 语言：** [English](README.en.md) · **简体中文**

> 一键摸清本机 AI Agent 的安全底数 — 暴露面、组件 CVE、MCP / Skills 资产，全部在本地完成。

**v0.1 初始预览** — 桌面壳、Hermes/OpenClaw 适配与规则库仍在快速迭代；API 与 UI 可能有破坏性变更，欢迎 Issue / PR 共建。

AgentSec 是以 **macOS 为主平台** 的桌面安全工具，专为 **Hermes** 与 **OpenClaw** 设计。它不替代你的 Agent，而是在旁边做一轮「体检」：扫配置与技能里的风险、查依赖里的已知漏洞，并让你在同一界面里管理 MCP、Skills、知识库与组件 — **数据不出本机，无遥测，无账号**。

![扫描结果概览](docs/screenshots/zh/02-results.png)

---

## 平台支持

| 平台 | 状态 | 说明 |
|------|------|------|
| **macOS** | ✅ 主要支持 | 日常开发与 `./scripts/package-dmg.sh` 发布 |
| **Windows** | 🧪 实验性 | 提供 `package-win.ps1` 与路径抽象；扫描与适配**尚未完整验证**，欢迎实测反馈 |

---

## 为什么用 AgentSec

| | 传统安全工具 | AgentSec |
|---|-------------|----------|
| 扫描对象 | 通用进程 / 容器 | **Agent 配置、Skill、MCP、依赖** |
| 风险类型 | CVE、端口 | **暴露面 + Prompt 注入规则 + CVE** 双管线 |
| 使用方式 | CLI / 服务端 | **桌面一键扫描**，结果可反复查看 |
| 数据 | 常需上报 | **纯本地**，快照脱敏后仅存本机 |

---

## 核心能力

**暴露面检测** — 集成 pyATR 规则库与 OpenClaw 安全审计，覆盖配置基线偏差、Prompt 注入、工具描述投毒、上下文外泄等 Agent 特有风险；发现项按来源与规则聚合，附带严重度分级、证据片段与文件定位，支持误报忽略与路径白名单。

**组件漏洞治理** — 基于 OSV 对 Agent 依赖做版本—CVE 关联，按组件聚合展示 CVSS、影响范围与修复版本；暴露面与 CVE 双管线解耦，CVE 数据源不可达时不阻断暴露面扫描结论。

**资产发现与处置** — 通过 Hermes / OpenClaw 适配器解析本机 MCP、Skill、知识库及包管理依赖，形成按 Agent 分组的资产清单；支持组件更新、禁用与卸载，关键操作可配置二次确认。

**权限态势评估** — 汇总 Agent 与挂载资产的权限声明，按文件、Shell、网络、工具、知识库等维度归一化；**权限矩阵**对比各组件能力覆盖，**雷达图**对比多 Agent 权限暴露面，辅助识别高危能力组合。

**统一运营视图** — 全机安全评分、待处置项队列与分 Agent 工作台联动；在同一应用内完成威胁研判、漏洞跟踪与资产运维，无需在扫描器与配置工具之间切换。

**本地可信执行** — 扫描、存储与展示均在设备侧完成；快照落盘前对凭证类字段脱敏，不采集遥测、不依赖云端账号。

---

## 快速开始

环境：**macOS** · Node.js ≥ 18 · Python ≥ 3.10

```bash
cd engine && python3 -m venv .venv && source .venv/bin/activate && pip install -e .
cd ../app && npm install && npm run dev
```

Electron 下载慢时可设：`ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"`

<details>
<summary>Windows 实验性开发（未完整验证）</summary>

在 Windows PowerShell 中：

```powershell
cd engine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
cd ..\app
npm install
npm run dev
```

Hermes / OpenClaw 默认仍从 `%USERPROFILE%\.hermes` / `%USERPROFILE%\.openclaw` 发现；若路径或行为与 macOS 不一致，请提 Issue。
</details>

---

## 打包发布

**PyInstaller 冻结的 Python 引擎必须在目标操作系统上构建**（无法在 Mac 上直接产出可在 Windows 运行的 `.exe`）。Electron 前端可在各平台分别打包；推荐用仓库内一键脚本。

> **macOS DMG 当前未做 Apple 代码签名。** 首次打开若被 Gatekeeper 拦截，请在「系统设置 → 隐私与安全性」中允许，或右键 App → 打开。

### macOS（DMG）

在 macOS 上执行：

```bash
./scripts/package-dmg.sh
```

| 参数 | 说明 |
|------|------|
| `--skip-engine` | 跳过 PyInstaller（引擎未改时可加速） |
| `--skip-npm-install` | 跳过 `npm install` |

产物：`app/release/AgentSec-*.dmg`  
图标：`app/build/icon.icns`

### Windows（NSIS 安装包 · 实验性）

在 Windows 上打开 PowerShell（项目根目录）：

```powershell
.\scripts\package-win.ps1
```

| 参数 | 说明 |
|------|------|
| `-SkipEngine` | 跳过 PyInstaller |
| `-SkipNpmInstall` | 跳过 `npm install` |

产物：`app/release/AgentSec Setup *.exe`  
Windows 图标 `app/build/icon.ico` 尚未随仓库提供，打包时将使用 electron-builder 默认图标。

### 手动分步（`app/` 目录）

```bash
npm run build:engine   # 调用 ../scripts/build-engine.cjs，须在对应 OS 上执行
npm run build          # TypeScript + Vite + Electron 主进程
npm run dist:mac       # electron-builder → dmg
npm run dist:win       # electron-builder → NSIS（在 Windows 上执行）
```

国内网络可设：`ELECTRON_BUILDER_BINARIES_MIRROR="https://npmmirror.com/mirrors/electron-builder-binaries/"`

---

## 配置

AgentSec 使用统一配置文件 **`config.json`**，与扫描快照、日志位于同一数据目录。设置页的选项会写入该文件；引擎与 Electron 主进程读取同一份配置。

| 平台 | 默认路径 |
|------|----------|
| macOS | `~/Library/Application Support/AgentSec/config.json` |
| Windows | `%APPDATA%\AgentSec\config.json` |

完整字段示例见 [`docs/config.example.json`](docs/config.example.json)。主要节：

| 节 | 说明 |
|----|------|
| `ui` | 语言、主题、资产操作确认（设置页可改） |
| `scan` | `cve_online`：是否联网查询 OSV（设置页可改） |
| `agents` | `hermes_home` / `openclaw_home` / `*_bin`：Agent 路径与 CLI |
| `dev` | `debug`、`engine_dir`、`python`：开发调试 |

**优先级：** 环境变量 > `config.json` > 内置默认。环境变量适合 CI 或临时覆盖；日常使用请改配置文件或设置页。

| 环境变量 | 覆盖项 |
|----------|--------|
| `AGENTSEC_DATA_DIR` | 整个数据目录（含 config.json 位置） |
| `AGENTSEC_*_HOME` / `AGENTSEC_*_BIN` | 对应 `agents.*` 字段 |
| `AGENTSEC_CVE_OFFLINE` | 任意非空 → `scan.cve_online=false` |
| `AGENTSEC_DEBUG` | `1` → `dev.debug=true` |
| `AGENTSEC_ENGINE_DIR` / `AGENTSEC_PYTHON` | 开发态引擎路径 |

> 旧版目录 `~/Library/Application Support/agentSec/`（小写）**不会自动迁移**；旧版 UI 设置若存于浏览器 localStorage，首次启动会自动合并进 `config.json`。

更多设计说明见 [`docs/`](docs/)。

---

## 第三方组件

| 组件 | 用途 | 说明 |
|------|------|------|
| [pyATR](https://pypi.org/project/pyatr/) | 暴露面规则检测 | 内置 ATR 规则包，离线匹配 |
| [OSV](https://osv.dev/) | CVE 查询 | 联网查询依赖漏洞（可失败降级） |
| [cvss](https://pypi.org/project/cvss/) | CVSS 解析 | 评分展示 |
| OpenClaw 安全审计规则 | 暴露面补充 | 与 pyATR 并行，见 `engine/agentsec_engine/detectors/` |

UI 栈：Electron · React · Vite · TypeScript。

---

## 参与与许可

欢迎 Issue / PR。UI 改动前建议：`cd app && npx tsc --noEmit`

Copyright © 2026 [ChuhC](https://github.com/ChuhC). 本项目采用 [AGPL-3.0](LICENSE) 许可。若你将修改版作为网络服务提供，须向用户提供对应源代码。

安全问题请阅读 [SECURITY.md](SECURITY.md)，通过 GitHub Security Advisories 私下反馈，勿公开 Issue 披露可利用漏洞。

# AgentSec

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/ChuhC/AgentSec/releases)

> 本机 AI Agent 安全体检 — 暴露面、CVE、MCP / Skills 资产，纯本地完成。  
> **v0.1 初始预览**：功能与适配仍在快速迭代，欢迎 Issue / PR。

![扫描结果概览](docs/screenshots/zh/02-results.png)

**Languages / 语言：** [**English**](README.en.md) · [**简体中文**](README.zh-CN.md)

| | |
|---|---|
| **主平台** | macOS（开发 + DMG 发布） |
| **适配 Agent** | Hermes · OpenClaw |
| **许可** | [AGPL-3.0](LICENSE) |
| **安全反馈** | [SECURITY.md](SECURITY.md) |
| **设计文档** | [`docs/`](docs/) |

---

## 快速链接

- **macOS 开发**：见 [README.zh-CN.md § 快速开始](README.zh-CN.md#快速开始) 或 [README.en.md § Quick start](README.en.md#quick-start)
- **打包 DMG**：`./scripts/package-dmg.sh` → `app/release/AgentSec-*.dmg`（当前构建**未代码签名**）
- **Windows**：实验性打包脚本 `scripts/package-win.ps1`，扫描能力尚未完整验证

完整说明、平台支持表与第三方依赖声明见中英文 README。

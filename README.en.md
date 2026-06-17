# AgentSec

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

**Languages / 语言：** **English** · [简体中文](README.zh-CN.md)

> Know your local AI agents' security posture — exposure, CVEs, and MCP / Skills assets, all on-device.

AgentSec is a **macOS desktop security scanner** built for **Hermes** and **OpenClaw**. It does not replace your agents; it runs a local health check: surface misconfigurations and risky skills, match dependencies against known CVEs, and let you manage MCP servers, Skills, knowledge bases, and packages in one place — **no cloud, no telemetry, no account**.

![Scan results](docs/screenshots/en/02-results.png)

---

## Why AgentSec

| | Typical security tools | AgentSec |
|---|------------------------|----------|
| What it scans | Processes, containers | **Agent configs, Skills, MCP, dependencies** |
| Risk coverage | CVEs, ports | **Exposure + injection rules + CVE** in parallel |
| How you use it | CLI / server-side | **One-click desktop scan**, revisitable results |
| Your data | Often uploaded | **Stays on your Mac**, redacted snapshots only |

---

## Highlights

**Exposure detection** — pyATR rule packs plus OpenClaw security audit for agent-specific risks: baseline drift, prompt injection, tool-description poisoning, and context exfiltration. Findings aggregate by source and rule ID with severity tiers, evidence snippets, file locations, and ignore / path-whitelist workflows.

**Vulnerability management** — OSV-backed correlation between dependency versions and known CVEs, rolled up per component with CVSS, blast radius, and fix versions. Exposure and CVE pipelines are decoupled: a failed CVE feed does not block exposure results.

**Asset discovery & response** — Hermes / OpenClaw adapters inventory local MCP servers, skills, knowledge bases, and package dependencies per agent. Supports update, disable, and uninstall with configurable confirmation gates.

**Permission posture** — Normalizes declared permissions from agents and attached assets across file, shell, network, tool, and knowledge-base categories; radar comparison highlights over-privileged agents and high-risk capability mixes.

**Unified operations** — Fleet-wide security score, remediation queue, and per-agent workbench tie together threat review, CVE tracking, and asset ops without switching between separate scanners and config tools.

**Local trust boundary** — Scan, persist, and render entirely on-device. Snapshots are redacted for credential-like fields before storage. No telemetry and no cloud account required.

---

## Quick start

Requires macOS · Node.js ≥ 18 · Python ≥ 3.10

```bash
cd engine && python3 -m venv .venv && source .venv/bin/activate && pip install -e .
cd ../app && npm install && npm run dev
```

Slow Electron downloads: `ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"`

macOS app bundle: `./scripts/package-dmg.sh` → `app/release/AgentSec-*.dmg`

| Variable | Purpose |
|----------|---------|
| `AGENTSEC_DATA_DIR` | Data dir (default `~/Library/Application Support/agentSec/`) |
| `AGENTSEC_DEBUG` | `1` for verbose logs |

Further docs in [`docs/`](docs/).

---

## Contributing & license

Issues and PRs welcome. Before UI changes: `cd app && npx tsc --noEmit`

Individual developer project under [AGPL-3.0](LICENSE). Network-deployed modifications must offer corresponding source to users.

Report security issues via GitHub Security Advisories.

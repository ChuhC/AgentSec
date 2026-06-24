# AgentSec

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/ChuhC/AgentSec/releases)

**Language / 语言：** **English** · [简体中文](README.zh-CN.md)

> One-click local scans for your AI agents — exposure risks, dependency CVEs, and MCP / Skills assets. Everything stays on your device.

**v0.1 early preview** — Actively evolving; UI and APIs may change. Issues and PRs welcome.

AgentSec is a **macOS-first desktop security scanner** built for **Hermes** and **OpenClaw**. It does not replace your agents; it runs a local health check: surface misconfigurations and risky skills, match dependencies against known CVEs, and let you manage MCP servers, Skills, knowledge bases, and packages in one place — **no cloud, no telemetry, no account**.

![Scan results](docs/screenshots/en/02-results.png)

---

## Platform support

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** | ✅ Primary | Day-to-day dev and `./scripts/package-dmg.sh` releases |
| **Windows** | 🧪 Experimental | `package-win.ps1` and path abstractions exist; **scanning not fully validated** — feedback welcome |

---

## Why AgentSec

| | Typical security tools | AgentSec |
|---|------------------------|----------|
| What it scans | Processes, containers | **Agent configs, Skills, MCP, dependencies** |
| Risk coverage | CVEs, ports | **Exposure + injection rules + CVE** in parallel |
| How you use it | CLI / server-side | **One-click desktop scan**, revisitable results |
| Your data | Often uploaded | **Stays on your device**, redacted snapshots only |

---

## Highlights

**Exposure detection** — pyATR rule packs plus OpenClaw security audit for agent-specific risks: baseline drift, prompt injection, tool-description poisoning, and context exfiltration. Findings aggregate by source and rule ID with severity tiers, evidence snippets, file locations, and ignore / path-whitelist workflows.

**Vulnerability management** — OSV-backed correlation between dependency versions and known CVEs, rolled up per component with CVSS, blast radius, and fix versions. Exposure and CVE pipelines are decoupled: a failed CVE feed does not block exposure results.

**Asset discovery & response** — Hermes / OpenClaw adapters inventory local MCP servers, skills, knowledge bases, and package dependencies per agent. Supports update, disable, and uninstall with configurable confirmation gates.

**Permission posture** — Normalizes declared permissions from agents and attached assets across file, shell, network, tool, and knowledge-base categories; a **permission matrix** compares capability coverage per component, and **radar charts** compare agents to spot over-privileged or risky capability mixes.

**Unified operations** — Fleet-wide security score, remediation queue, and per-agent workbench tie together threat review, CVE tracking, and asset ops without switching between separate scanners and config tools.

**Local trust boundary** — Scan, persist, and render entirely on-device. Snapshots are redacted for credential-like fields before storage. No telemetry and no cloud account required.

---

## Quick start

Requires **macOS** · Node.js ≥ 18 · Python ≥ 3.10

```bash
cd engine && python3 -m venv .venv && source .venv/bin/activate && pip install -e .
cd ../app && npm install && npm run dev
```

Slow Electron downloads: `ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"`

<details>
<summary>Windows experimental dev (not fully validated)</summary>

In Windows PowerShell:

```powershell
cd engine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
cd ..\app
npm install
npm run dev
```

Discovery still defaults to `%USERPROFILE%\.hermes` and `%USERPROFILE%\.openclaw`. Report Issues if paths or behavior differ from macOS.
</details>

---

## Building releases

The **PyInstaller-frozen Python engine must be built on the target OS** (you cannot produce a runnable Windows `.exe` engine from macOS alone). Package the Electron shell on each platform separately; use the repo scripts below.

> **macOS DMG builds are currently unsigned.** If Gatekeeper blocks the app, allow it under System Settings → Privacy & Security, or right-click the app → Open.

### macOS (DMG)

On macOS:

```bash
./scripts/package-dmg.sh
```

| Flag | Purpose |
|------|---------|
| `--skip-engine` | Skip PyInstaller (faster when the engine unchanged) |
| `--skip-npm-install` | Skip `npm install` |

Output: `app/release/AgentSec-*.dmg`  
Icon: `app/build/icon.icns`

### Windows (NSIS installer · experimental)

In PowerShell from the repo root on Windows:

```powershell
.\scripts\package-win.ps1
```

| Flag | Purpose |
|------|---------|
| `-SkipEngine` | Skip PyInstaller |
| `-SkipNpmInstall` | Skip `npm install` |

Output: `app/release/AgentSec Setup *.exe`  
`app/build/icon.ico` is not shipped yet; Windows builds fall back to the electron-builder default icon.

### Manual steps (from `app/`)

```bash
npm run build:engine   # runs ../scripts/build-engine.cjs on the current OS
npm run build          # TypeScript + Vite + Electron main
npm run dist:mac       # electron-builder → dmg
npm run dist:win       # electron-builder → NSIS (run on Windows)
```

Mirror for electron-builder binaries (optional):  
`ELECTRON_BUILDER_BINARIES_MIRROR="https://npmmirror.com/mirrors/electron-builder-binaries/"`

---

## Configuration

AgentSec uses a single **`config.json`** alongside scan snapshots and logs. Settings in the app UI are persisted there; the Electron shell and Python engine read the same file.

| Platform | Default path |
|----------|--------------|
| macOS | `~/Library/Application Support/AgentSec/config.json` |
| Windows | `%APPDATA%\AgentSec\config.json` |

See [`docs/config.example.json`](docs/config.example.json) for all fields:

| Section | Purpose |
|---------|---------|
| `ui` | Language, theme, asset confirmation gates (editable in Settings) |
| `scan` | `cve_online`: query OSV over the network (editable in Settings) |
| `agents` | `hermes_home` / `openclaw_home` / `*_bin`: agent paths and CLIs |
| `dev` | `debug`, `engine_dir`, `python`: development overrides |

**Precedence:** environment variables > `config.json` > built-in defaults. Use env vars for CI or temporary overrides; prefer the config file or Settings UI for day-to-day use.

| Variable | Overrides |
|----------|-----------|
| `AGENTSEC_DATA_DIR` | Entire data directory (including config location) |
| `AGENTSEC_*_HOME` / `AGENTSEC_*_BIN` | Matching `agents.*` fields |
| `AGENTSEC_CVE_OFFLINE` | Any non-empty value → `scan.cve_online=false` |
| `AGENTSEC_DEBUG` | `1` → `dev.debug=true` |
| `AGENTSEC_ENGINE_DIR` / `AGENTSEC_PYTHON` | Dev engine paths |

> Legacy data under `~/Library/Application Support/agentSec/` (lowercase) is **not migrated automatically**. Legacy UI settings in browser localStorage are merged into `config.json` on first launch.

Further docs in [`docs/`](docs/).

---

## Third-party components

| Component | Role | Notes |
|-----------|------|-------|
| [pyATR](https://pypi.org/project/pyatr/) | Exposure rules | Bundled ATR rule packs, offline matching |
| [OSV](https://osv.dev/) | CVE lookup | Network query for dependency CVEs (graceful degradation) |
| [cvss](https://pypi.org/project/cvss/) | CVSS parsing | Severity display |
| OpenClaw security audit rules | Exposure supplement | Parallel to pyATR; see `engine/agentsec_engine/detectors/` |

UI stack: Electron · React · Vite · TypeScript.

---

## Contributing & license

Issues and PRs welcome. Before UI changes: `cd app && npx tsc --noEmit`

Copyright © 2026 [ChuhC](https://github.com/ChuhC). Licensed under [AGPL-3.0](LICENSE). Network-deployed modifications must offer corresponding source to users.

Report security issues via [SECURITY.md](SECURITY.md) and GitHub Security Advisories — do not file public Issues for exploitable vulnerabilities.

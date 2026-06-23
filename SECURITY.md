# Security Policy

AgentSec is a **local-first** desktop scanner. It reads agent configs on your machine, may query public CVE feeds (OSV), and stores redacted scan snapshots under your user data directory. It does not phone home for telemetry.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Initial preview — security fixes on a best-effort basis |

## Reporting a vulnerability

**Please do not open public GitHub Issues for exploitable security problems.**

1. Open a **[GitHub Security Advisory](https://github.com/ChuhC/AgentSec/security/advisories/new)** (preferred), or
2. Email the maintainer via the contact address on their GitHub profile if Advisories are unavailable.

Include:

- Affected version (e.g. `0.1.0` DMG or git commit)
- Platform (macOS / Windows)
- Steps to reproduce
- Impact assessment (local privilege, data exfiltration, RCE, etc.)

## Scope

In scope:

- Remote code execution or sandbox escape via malicious scan input or IPC
- Credential or secret leakage beyond documented redaction behavior
- Unsafe file read/write outside intended scan/management paths

Out of scope (for now):

- Findings **inside scanned agent configs** (e.g. exposed API keys in `~/.hermes`) — report those to the agent vendor or rotate credentials
- Missing code signing on macOS DMG builds (documented; use Gatekeeper override at your own risk)
- Denial-of-service from extremely large local skill trees (performance hardening welcome via PR)

## Response

This is a solo-maintainer preview project. Expect a **best-effort** response within a reasonable timeframe. Critical issues affecting local confidentiality or integrity will be prioritized.

## Safe harbor

Good-faith research on your own installation is appreciated. Do not test against systems you do not own or lack permission to assess.

"""Agent 版本更新检测（Hermes / OpenClaw 官方 CLI + registry 兜底）。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .registry_client import fetch_npm_latest, fetch_pypi_latest

_CHECK_TIMEOUT = 90
_UPDATE_TIMEOUT = 1800
_COMMITS_BEHIND_RE = re.compile(r"(\d+)\s+commits?\s+behind", re.I)
_UPDATE_CHECK_MAX_AGE = 6 * 3600
_VER_TOKEN = re.compile(r"[0-9][\w.\-]*")


def _normalize_version(ver: Optional[str]) -> str:
    if not ver:
        return ""
    s = str(ver).strip().lstrip("vV")
    m = _VER_TOKEN.search(s)
    return m.group(0) if m else s


def _version_tuple(ver: str) -> tuple:
    parts = []
    for p in _normalize_version(ver).replace("-", ".").split("."):
        num = re.match(r"(\d+)", p)
        parts.append(int(num.group(1)) if num else 0)
    return tuple(parts)


def _is_newer(latest: str, current: str) -> bool:
    la, cu = _normalize_version(latest), _normalize_version(current)
    if not la or not cu:
        return bool(la and la != cu)
    try:
        return _version_tuple(la) > _version_tuple(cu)
    except (ValueError, TypeError):
        return la != cu


def _with_v(ver: str) -> str:
    s = _normalize_version(ver)
    return f"v{s}" if s else ""


@dataclass
class AgentUpdateInfo:
    update_available: bool = False
    current_version: str = ""
    latest_version: str = ""
    update_method: str = "manual"  # git | pip | npm | manual
    can_update: bool = False
    update_command: str = ""
    detail: str = ""


def _resolve_hermes_cli() -> Optional[str]:
    cli = os.environ.get("AGENTSEC_HERMES_BIN")
    if cli and os.path.isfile(cli):
        return cli
    return shutil.which("hermes")


def _resolve_openclaw_cli() -> Optional[str]:
    from .discovery import parsers

    return parsers.resolve_openclaw_cli()


def _read_update_check(home: str) -> dict:
    from .discovery import parsers

    return parsers.read_json(os.path.join(home, ".update_check")) or {}


def _hermes_install_method(home: str) -> str:
    if os.path.isfile("/.dockerenv"):
        return "manual"
    repo = Path(home) / "hermes-agent"
    if (repo / ".git").is_dir():
        return "git"
    return "pip"


def _run_hermes_update_check(cli: str, home: str) -> Optional[int]:
    """运行 `hermes update --check`，返回 behind（None 表示未能解析）。"""
    try:
        proc = subprocess.run(
            [cli, "update", "--check"],
            capture_output=True,
            text=True,
            timeout=_CHECK_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _COMMITS_BEHIND_RE.search(text)
    if m:
        return int(m.group(1))
    if "update available" in text.lower():
        return 1
    uc = _read_update_check(home)
    behind = uc.get("behind")
    if isinstance(behind, int):
        return behind
    return 0 if "up to date" in text.lower() or "已是最新" in text else None


def _update_check_fresh(home: str) -> bool:
    uc = _read_update_check(home)
    ts = uc.get("ts")
    if not isinstance(ts, (int, float)):
        return False
    import time

    return (time.time() - float(ts)) < _UPDATE_CHECK_MAX_AGE


def check_hermes_update(
    home: str,
    *,
    online: bool = True,
    force: bool = False,
    current_version: str = "",
) -> AgentUpdateInfo:
    """Hermes：优先 `hermes update --check`，PyPI 作展示/ pip 安装兜底。"""
    uc = _read_update_check(home)
    current = _normalize_version(uc.get("ver") or current_version)
    method = _hermes_install_method(home)
    cli = _resolve_hermes_cli()

    behind: Optional[int] = None
    if cli and (force or not _update_check_fresh(home)):
        behind = _run_hermes_update_check(cli, home)
        uc = _read_update_check(home)
        if behind is None and isinstance(uc.get("behind"), int):
            behind = uc["behind"]
    elif isinstance(uc.get("behind"), int):
        behind = uc["behind"]

    pypi_latest = fetch_pypi_latest("hermes-agent") if online else None
    update_available = False
    detail = ""

    if behind is not None and behind != 0:
        update_available = True
        if behind > 0:
            detail = f"落后 origin/main {behind} 个 commit"
        else:
            detail = "有新版本可用"
    elif pypi_latest and current and _is_newer(pypi_latest, current):
        update_available = True
        detail = f"PyPI 最新 {pypi_latest}"

    latest = pypi_latest or current
    if not update_available:
        latest = current

    can_update = bool(cli) and method in ("git", "pip")
    update_command = "hermes update" if cli else ""
    if method == "manual":
        can_update = False
        update_command = "请按 Hermes 官方文档升级（Docker/Nix 等需 out-of-band 更新）"

    return AgentUpdateInfo(
        update_available=update_available,
        current_version=current,
        latest_version=latest,
        update_method=method,
        can_update=can_update,
        update_command=update_command,
        detail=detail,
    )


def check_openclaw_update(
    home: str,
    *,
    online: bool = True,
    current_version: str = "",
) -> AgentUpdateInfo:
    """OpenClaw：`openclaw update status --json`，与官方 update 通道一致。"""
    from .discovery import parsers

    current = _normalize_version(current_version) or _normalize_version(
        parsers.resolve_openclaw_installed_version()
    )
    cli = _resolve_openclaw_cli()
    if not cli or not online:
        latest = current
        return AgentUpdateInfo(
            current_version=current,
            latest_version=latest,
        )

    try:
        proc = subprocess.run(
            [cli, "update", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=_CHECK_TIMEOUT,
        )
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        latest = fetch_npm_latest("openclaw") or current
        update_available = bool(latest and current and _is_newer(latest, current))
        return AgentUpdateInfo(
            update_available=update_available,
            current_version=current,
            latest_version=latest if update_available else current,
            update_method="npm",
            can_update=bool(shutil.which("npm")),
            update_command=f"{cli} update --yes",
            detail=f"registry 最新 {latest}" if update_available else "",
        )

    reg = (data.get("update") or {}).get("registry") or {}
    avail = data.get("availability") or {}
    reg_latest = reg.get("latestVersion")
    latest = _normalize_version(avail.get("latestVersion") or reg_latest or current)
    update_available = bool(avail.get("available"))
    if not update_available and latest and current and _is_newer(latest, current):
        update_available = True

    detail_parts = []
    if avail.get("gitBehind"):
        detail_parts.append(f"git 落后 {avail['gitBehind']}")
    if update_available and latest:
        detail_parts.append(f"registry 最新 {latest}")
    detail = " · ".join(detail_parts)

    install_kind = (data.get("update") or {}).get("installKind", "")
    can_update = install_kind == "package" and bool(cli)
    update_command = f"{cli} update --yes" if cli else "npm install -g openclaw@latest"

    return AgentUpdateInfo(
        update_available=update_available,
        current_version=current,
        latest_version=latest if update_available else current,
        update_method="npm",
        can_update=can_update,
        update_command=update_command,
        detail=detail,
    )


def apply_update_info(agent, info: AgentUpdateInfo) -> None:
    """将 AgentUpdateInfo 写入 Agent 模型。"""
    if info.current_version:
        agent.version = _with_v(info.current_version)
    agent.latest_version = _with_v(info.latest_version or info.current_version)
    agent.update_available = info.update_available
    agent.can_update = info.can_update
    agent.update_method = info.update_method
    agent.update_command = info.update_command
    agent.update_detail = info.detail


def run_hermes_update(home: str) -> None:
    cli = _resolve_hermes_cli()
    if not cli:
        raise RuntimeError("未找到 hermes 命令，无法执行更新")
    try:
        proc = subprocess.run(
            [cli, "update", "-y"],
            capture_output=True,
            text=True,
            timeout=_UPDATE_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hermes update 超时（>{_UPDATE_TIMEOUT}s）") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else f"hermes update 失败（退出码 {proc.returncode}）")


def run_openclaw_update() -> None:
    cli = _resolve_openclaw_cli()
    if not cli:
        raise RuntimeError("未找到 openclaw 命令，无法执行更新")
    try:
        proc = subprocess.run(
            [cli, "update", "--yes", "--json"],
            capture_output=True,
            text=True,
            timeout=_UPDATE_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"openclaw update 超时（>{_UPDATE_TIMEOUT}s）") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else f"openclaw update 失败（退出码 {proc.returncode}）")

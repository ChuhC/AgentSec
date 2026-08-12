"""AssetManager：资产管理写操作 + 快照增量 patch（B3-b）。

操作：update / disable / enable / uninstall
  - 经各 Adapter / 包管理器（npm/pip）执行（MVP 模拟成功）
  - 成功后对 SnapshotStore 局部 patch（version/status），不改 Finding
  - 失败抛错 → IPC 返回错误 → UI 弹框（NF-A3）
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional

from .models import AssetStatus
from .store import SnapshotStore

_CMD_TIMEOUT = 120


class AssetOperationError(Exception):
    pass


def _pkg_argv(manager: str, action: str, pkg: str, version: Optional[str]) -> Optional[List[str]]:
    """构造真实包管理器命令。action ∈ {update, uninstall}。"""
    if manager == "npm":
        if action == "update":
            return ["npm", "install", f"{pkg}@{version}" if version else f"{pkg}@latest"]
        if action == "uninstall":
            return ["npm", "uninstall", pkg]
    elif manager == "pip":
        if action == "update":
            target = f"{pkg}=={version}" if version else pkg
            return ["pip", "install", "-U", target]
        if action == "uninstall":
            return ["pip", "uninstall", "-y", pkg]
    return None


def _run_pkg(manager: str, action: str, pkg: str, version: Optional[str], cwd: str) -> None:
    """真实执行包管理器命令；失败抛 AssetOperationError（NF-A3 禁止静默失败）。"""
    argv = _pkg_argv(manager, action, pkg, version)
    if not argv:
        raise AssetOperationError(f"不支持的操作：{manager} {action}")
    if manager == "pip":
        candidates = (
            os.path.join(cwd, ".venv", "bin", "pip"),
            os.path.join(cwd, "venv", "bin", "pip"),
            os.path.join(cwd, ".venv", "Scripts", "pip.exe"),
            os.path.join(cwd, "venv", "Scripts", "pip.exe"),
        )
        pip_exe = next((p for p in candidates if os.path.isfile(p)), None)
        if not pip_exe:
            raise AssetOperationError("未找到该 Agent 自身虚拟环境的 pip，拒绝修改系统 Python")
        argv[0] = pip_exe
    if os.path.isabs(argv[0]):
        command_exists = os.path.isfile(argv[0])
    else:
        command_exists = shutil.which(argv[0]) is not None
    if not command_exists:
        raise AssetOperationError(f"未找到 {argv[0]}，无法执行{('更新' if action == 'update' else '卸载')}")
    try:
        proc = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=_CMD_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise AssetOperationError(f"{argv[0]} 执行超时（>{_CMD_TIMEOUT}s）")
    except OSError as exc:
        raise AssetOperationError(f"{argv[0]} 执行失败：{exc}")
    if proc.returncode != 0:
        lines = [l.strip() for l in (proc.stderr or proc.stdout or "").splitlines() if l.strip()]
        # 优先选信息量大的错误行（含错误码/404），跳过“日志路径”这类噪声行
        meaningful = [
            l for l in lines
            if ("error" in l.lower() or "404" in l)
            and "complete log" not in l.lower()
            and not l.lower().startswith("npm error a ")
        ]
        detail = (meaningful or lines or [f"退出码 {proc.returncode}"])[0]
        raise AssetOperationError(f"{' '.join(argv)} 失败：{detail}")


def _installed_version(manager: str, install_path: str, pkg: str) -> Optional[str]:
    """回读包管理器装好的真实版本。"""
    if manager == "npm":
        pj = os.path.join(install_path, "node_modules", *pkg.split("/"), "package.json")
        data = _read_json_safe(pj)
        return data.get("version") if data else None
    if manager == "pip":
        candidates = (
            os.path.join(install_path, ".venv", "bin", "pip"),
            os.path.join(install_path, "venv", "bin", "pip"),
            os.path.join(install_path, ".venv", "Scripts", "pip.exe"),
            os.path.join(install_path, "venv", "Scripts", "pip.exe"),
        )
        pip_exe = next((p for p in candidates if os.path.isfile(p)), None)
        if not pip_exe:
            return None
        try:
            proc = subprocess.run([pip_exe, "show", pkg], cwd=install_path,
                                  capture_output=True, text=True, timeout=30)
            for line in (proc.stdout or "").splitlines():
                if line.lower().startswith("version:"):
                    return line.split(":", 1)[1].strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None


def _read_json_safe(path: str) -> Optional[dict]:
    import json
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _atomic_write_text(path: str, content: str) -> None:
    """同目录临时文件 + replace，保留原文件权限。"""
    directory = os.path.dirname(os.path.abspath(path))
    mode = os.stat(path).st_mode
    fd, tmp = tempfile.mkstemp(prefix=".agentsec-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise AssetOperationError(f"写入配置失败：{exc}") from exc


def _toggle_mcp_yaml(config_path: str, server_key: str, enable: bool) -> None:
    """ruamel 往返修改 config.yaml 的 mcp_servers.<key>.enabled（保留注释/格式）。

    原子写：先写临时文件再替换，避免部分写坏配置（NF-A3）。
    """
    try:
        from ruamel.yaml import YAML
    except ImportError:
        raise AssetOperationError("缺少 ruamel.yaml，无法安全修改配置")
    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.load(f)
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}")
    if not isinstance(data, dict):
        raise AssetOperationError("MCP 配置不是有效的 YAML 对象")
    servers = data.get("mcp_servers") or {}
    if (
        not isinstance(servers, dict)
        or server_key not in servers
        or not isinstance(servers[server_key], dict)
    ):
        raise AssetOperationError(f"配置中未找到 MCP 服务 {server_key}")
    servers[server_key]["enabled"] = bool(enable)
    try:
        stream = io.StringIO()
        yaml.dump(data, stream)
        _atomic_write_text(config_path, stream.getvalue())
    except AssetOperationError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssetOperationError(f"序列化 YAML 配置失败：{exc}") from exc


def _toggle_mcp_json(config_path: str, server_key: str, enable: bool) -> None:
    import json

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}") from exc
    except ValueError as exc:
        raise AssetOperationError(f"解析 JSON 配置失败：{exc}") from exc
    if not isinstance(data, dict):
        raise AssetOperationError("MCP 配置不是有效的 JSON 对象")
    root_key = (
        "mcp_servers"
        if isinstance(data.get("mcp_servers"), dict)
        else "mcpServers"
        if isinstance(data.get("mcpServers"), dict)
        else ""
    )
    servers = data.get(root_key) if root_key else None
    if (
        not isinstance(servers, dict)
        or server_key not in servers
        or not isinstance(servers[server_key], dict)
    ):
        raise AssetOperationError(f"配置中未找到 MCP 服务 {server_key}")
    servers[server_key]["enabled"] = bool(enable)
    _atomic_write_text(
        config_path,
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    )


def _toggle_mcp_toml(config_path: str, server_key: str, enable: bool) -> None:
    """最小化修改 Codex TOML 的对应 mcp_servers 表，保留其余格式与注释。"""
    try:
        import tomllib

        with open(config_path, "rb") as f:
            parsed = tomllib.load(f)
        servers = parsed.get("mcp_servers") or {}
    except (OSError, ValueError) as exc:
        raise AssetOperationError(f"解析 TOML 配置失败：{exc}") from exc
    if not isinstance(servers, dict) or server_key not in servers:
        raise AssetOperationError(f"配置中未找到 MCP 服务 {server_key}")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}") from exc

    section_start = None
    section_end = len(lines)
    section_re = re.compile(r"^\s*\[\s*mcp_servers\.(.+?)\s*\]\s*(?:#.*)?$")
    any_section_re = re.compile(r"^\s*\[")
    for index, line in enumerate(lines):
        match = section_re.match(line.rstrip("\r\n"))
        if not match:
            continue
        try:
            probe = tomllib.loads(
                f"[mcp_servers.{match.group(1)}]\n_agentsec_probe = true\n"
            )
            keys = list((probe.get("mcp_servers") or {}).keys())
        except ValueError:
            keys = []
        if keys and str(keys[0]) == server_key:
            section_start = index
            for end in range(index + 1, len(lines)):
                if any_section_re.match(lines[end]):
                    section_end = end
                    break
            break
    if section_start is None:
        raise AssetOperationError(f"无法定位 MCP 服务配置段 {server_key}")

    enabled_re = re.compile(
        r"^(\s*enabled\s*=\s*)(?:true|false)(\s*(?:#.*)?(?:\r?\n)?)$",
        re.I,
    )
    replacement = "true" if enable else "false"
    for index in range(section_start + 1, section_end):
        match = enabled_re.match(lines[index])
        if match:
            newline = "\n" if lines[index].endswith("\n") else ""
            suffix = match.group(2).rstrip("\r\n")
            lines[index] = f"{match.group(1)}{replacement}{suffix}{newline}"
            break
    else:
        lines.insert(section_start + 1, f"enabled = {replacement}\n")
    _atomic_write_text(config_path, "".join(lines))


def _toggle_mcp_config(config_path: str, server_key: str, enable: bool) -> None:
    suffix = os.path.splitext(config_path)[1].lower()
    if suffix == ".json":
        _toggle_mcp_json(config_path, server_key, enable)
    elif suffix == ".toml":
        _toggle_mcp_toml(config_path, server_key, enable)
    elif suffix in (".yaml", ".yml"):
        _toggle_mcp_yaml(config_path, server_key, enable)
    else:
        raise AssetOperationError(
            f"不支持的 MCP 配置格式：{suffix or '未知'}"
        )


def _toggle_openclaw_skill_json(config_path: str, config_key: str, enable: bool) -> None:
    """写 openclaw.json 的 skills.entries.<key>.enabled。"""
    if not config_key.startswith("skills:"):
        raise AssetOperationError(f"不支持的 Skill 配置键：{config_key}")
    skill_key = config_key.split(":", 1)[1]
    import json

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}")
    except ValueError as exc:
        raise AssetOperationError(f"解析配置失败：{exc}")

    skills = data.setdefault("skills", {})
    if not isinstance(skills, dict):
        skills = {}
        data["skills"] = skills
    entries = skills.setdefault("entries", {})
    if not isinstance(entries, dict):
        entries = {}
        skills["entries"] = entries
    entry = entries.get(skill_key)
    if not isinstance(entry, dict):
        entry = {}
        entries[skill_key] = entry
    entry["enabled"] = bool(enable)

    tmp = config_path + ".agentsec.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, config_path)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise AssetOperationError(f"写入配置失败：{exc}")


def _toggle_channel_json(config_path: str, config_key: str, enable: bool) -> None:
    """原子修改 JSON 配置中的 channels.* / platforms.*.enabled。"""
    import json

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}")
    except ValueError as exc:
        raise AssetOperationError(f"解析配置失败：{exc}")

    if ":" not in config_key:
        raise AssetOperationError(f"不支持的通道配置键：{config_key}")
    root, name = config_key.split(":", 1)
    if root not in ("channels", "platforms"):
        raise AssetOperationError(f"不支持的通道配置键：{config_key}")
    section = (data or {}).get(root) or {}
    if name not in section or not isinstance(section[name], dict):
        raise AssetOperationError(f"配置中未找到通道 {name}")
    section[name]["enabled"] = bool(enable)

    tmp = config_path + ".agentsec.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, config_path)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise AssetOperationError(f"写入配置失败：{exc}")


def _toggle_channel_yaml(config_path: str, config_key: str, enable: bool) -> None:
    """ruamel 往返修改 YAML 配置中的 channels.* / platforms.*.enabled。"""
    try:
        from ruamel.yaml import YAML
    except ImportError:
        raise AssetOperationError("缺少 ruamel.yaml，无法安全修改配置")
    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.load(f)
    except OSError as exc:
        raise AssetOperationError(f"读取配置失败：{exc}")

    data = data or {}
    if ":" not in config_key:
        raise AssetOperationError(f"不支持的通道配置键：{config_key}")
    root, name = config_key.split(":", 1)
    if root not in ("channels", "platforms"):
        raise AssetOperationError(f"不支持的通道配置键：{config_key}")
    section = data.get(root) or {}
    if name not in section:
        raise AssetOperationError(f"配置中未找到通道 {name}")
    section[name]["enabled"] = bool(enable)

    tmp = config_path + ".agentsec.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.dump(data, f)
        os.replace(tmp, config_path)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise AssetOperationError(f"写入配置失败：{exc}")


def _toggle_channel_config(config_path: str, config_key: str, enable: bool) -> None:
    if config_path.endswith(".json"):
        _toggle_channel_json(config_path, config_key, enable)
    else:
        _toggle_channel_yaml(config_path, config_key, enable)


class AssetManager:
    def __init__(self, store: SnapshotStore):
        self.store = store

    def _find_asset(self, asset_id: str) -> Optional[dict]:
        snap = self.store.load()
        if not snap:
            return None
        for a in snap.get("assets", []):
            if a.get("id") == asset_id:
                return a
        return None

    def update(self, asset_id: str) -> Dict:
        asset = self._find_asset(asset_id)
        if not asset:
            raise AssetOperationError("未找到该组件")
        if not asset.get("can_update"):
            raise AssetOperationError("该组件不支持更新")
        manager = asset.get("manager")
        install_path = asset.get("install_path")
        target = asset.get("latest_version")  # 已知目标版本；依赖通常为 None → 升到 latest
        if manager and install_path:
            pkg = asset.get("package_name") or asset.get("name")
            _run_pkg(manager, "update", pkg, target, install_path)
            # 回读真实安装版本（npm），保证快照与磁盘一致
            new_version = _installed_version(manager, install_path, pkg) or target or asset.get("version")
        else:
            new_version = target or asset.get("version")
        snap = self.store.patch_asset(asset_id, {
            "version": new_version,
            "latest_version": None,
            "status": AssetStatus.ENABLED.value,
            "can_update": False,
        })
        return snap

    def disable(self, asset_id: str) -> Dict:
        asset = self._find_asset(asset_id)
        if not asset:
            raise AssetOperationError("未找到该组件")
        if not asset.get("can_disable", True):
            raise AssetOperationError("该组件不支持禁用")
        patch = {"status": AssetStatus.DISABLED.value}
        new_path = self._apply_toggle(asset, enable=False)
        if new_path:
            patch["path"] = new_path
        return self.store.patch_asset(asset_id, patch)

    def enable(self, asset_id: str) -> Dict:
        asset = self._find_asset(asset_id)
        if not asset:
            raise AssetOperationError("未找到该组件")
        if not asset.get("can_disable", True):
            raise AssetOperationError("该组件不支持启用")
        patch = {"status": AssetStatus.ENABLED.value}
        new_path = self._apply_toggle(asset, enable=True)
        if new_path:
            patch["path"] = new_path
        return self.store.patch_asset(asset_id, patch)

    def _apply_toggle(self, asset: dict, enable: bool) -> Optional[str]:
        """真机可逆启停。返回更新后的 path，否则 None。

        - skill：OpenClaw 写 openclaw.json 的 skills.entries.<key>.enabled
        - mcp  ：ruamel 往返写 config.yaml 的 enabled 标志（保留注释/格式）
        - channel：写 config 中 channels.* / platforms.*.enabled
        无真实句柄（path/config_key）→ 仅快照模拟。
        """
        atype = asset.get("type")
        path = asset.get("path")
        config_key = asset.get("config_key") or ""
        if atype == "skill" and path and config_key.startswith("skills:"):
            if path.endswith(".json"):
                _toggle_openclaw_skill_json(path, config_key, enable)
                return None
            raise AssetOperationError("该 Skill 不支持通过配置启停")
        if atype == "mcp" and path and config_key:
            _toggle_mcp_config(path, asset["config_key"], enable)
            return None
        if atype == "channel" and path and asset.get("config_key"):
            _toggle_channel_config(path, asset["config_key"], enable)
            return None
        raise AssetOperationError("该组件缺少可安全写回的配置句柄")

    def uninstall(self, asset_id: str) -> Dict:
        asset = self._find_asset(asset_id)
        if not asset:
            raise AssetOperationError("未找到该组件")
        if not asset.get("can_uninstall", False):
            raise AssetOperationError("该组件不支持卸载")
        # 有执行上下文 → 真实调包管理器卸载；否则 MVP 模拟（仅从快照移除）
        manager = asset.get("manager")
        install_path = asset.get("install_path")
        if manager and install_path:
            pkg = asset.get("package_name") or asset.get("name")
            _run_pkg(manager, "uninstall", pkg, None, install_path)
        snap = self.store.load()
        snap["assets"] = [a for a in snap.get("assets", []) if a.get("id") != asset_id]
        return self.store.write_full(snap)

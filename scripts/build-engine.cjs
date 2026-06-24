#!/usr/bin/env node
/** 跨平台 PyInstaller 冻结 agentsec-engine（须在目标 OS 上运行）。 */
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const ENGINE = path.join(ROOT, "engine");
const isWin = process.platform === "win32";
const macArch = process.env.AGENTSEC_MAC_ARCH;
const useRosetta =
  process.platform === "darwin" &&
  macArch === "x64" &&
  os.arch() === "arm64";

const venvPy = isWin
  ? path.join(ENGINE, ".venv", "Scripts", "python.exe")
  : path.join(ENGINE, ".venv", "bin", "python");

const py = fs.existsSync(venvPy) ? venvPy : isWin ? "python" : "python3";

const args = [
  "-m",
  "PyInstaller",
  "--onedir",
  "--name",
  "agentsec-engine",
  "--noconfirm",
  "--clean",
  "--distpath",
  "dist_pkg",
  "--workpath",
  "build_pkg",
  "--paths",
  ".",
  "--collect-all",
  "pyatr",
  "--collect-all",
  "cvss",
  "--collect-all",
  "ruamel",
  "--collect-submodules",
  "agentsec_engine",
  "packaging/run_engine.py",
];

if (useRosetta) {
  console.log("==> build-engine (x64 via Rosetta):", py, args.join(" "));
} else {
  console.log("==> build-engine:", py, args.join(" "));
}

const result = useRosetta
  ? spawnSync("arch", ["-x86_64", py, ...args], { cwd: ENGINE, stdio: "inherit" })
  : spawnSync(py, args, { cwd: ENGINE, stdio: "inherit" });
process.exit(result.status ?? 1);

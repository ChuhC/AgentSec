import { app } from "electron";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** 与 engine/agentsec_engine/paths.py APP_DATA_DIR_NAME 一致 */
export const APP_DATA_DIR_NAME = "AgentSec";

export function engineDir(appRoot: string): string {
  return process.env.AGENTSEC_ENGINE_DIR || path.join(appRoot, "..", "engine");
}

export function venvPythonPath(engineRoot: string): string {
  if (process.platform === "win32") {
    return path.join(engineRoot, ".venv", "Scripts", "python.exe");
  }
  return path.join(engineRoot, ".venv", "bin", "python");
}

export function resolvePython(engineRoot: string): string {
  if (process.env.AGENTSEC_PYTHON) return process.env.AGENTSEC_PYTHON;
  const venv = venvPythonPath(engineRoot);
  if (existsSync(venv)) return venv;
  return process.platform === "win32" ? "python" : "python3";
}

export function frozenEngineFilename(): string {
  return process.platform === "win32" ? "agentsec-engine.exe" : "agentsec-engine";
}

export function packagedEngineDir(): string {
  return path.join(process.resourcesPath, "engine");
}

export function resolveEngine(appRoot: string): { cmd: string; args: string[]; cwd: string } {
  if (app.isPackaged) {
    const dir = packagedEngineDir();
    return { cmd: path.join(dir, frozenEngineFilename()), args: [], cwd: dir };
  }
  return {
    cmd: resolvePython(engineDir(appRoot)),
    args: ["-m", "agentsec_engine"],
    cwd: engineDir(appRoot),
  };
}

/** 传给 Python 引擎的数据目录；打包态与 Electron userData 对齐 */
export function resolveDataDir(): string | undefined {
  if (process.env.AGENTSEC_DATA_DIR) return process.env.AGENTSEC_DATA_DIR;
  if (app.isPackaged) return app.getPath("userData");
  return undefined;
}

export function enginePathExtras(): string[] {
  const home = os.homedir();
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return [
      path.join(appData, "npm"),
      path.join(home, "AppData", "Local", "Programs", "Python", "Python313"),
      path.join(home, "AppData", "Local", "Programs", "Python", "Python312"),
      path.join(home, "AppData", "Local", "Programs", "Python", "Python311"),
    ];
  }
  return [
    path.join(home, ".npm-global", "bin"),
    path.join(home, ".local", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
  ];
}

export function enginePathEnv(): string {
  return [...enginePathExtras(), process.env.PATH ?? ""].filter(Boolean).join(path.delimiter);
}

export function engineChildEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
    PATH: enginePathEnv(),
  };
  const dataDir = resolveDataDir();
  if (dataDir) env.AGENTSEC_DATA_DIR = dataDir;
  return env;
}

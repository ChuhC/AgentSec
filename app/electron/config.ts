import { app } from "electron";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** 与 engine/agentsec_engine/paths.py APP_DATA_DIR_NAME 一致 */
export const APP_DATA_DIR_NAME = "AgentSec";

export const CONFIG_FILENAME = "config.json";

export interface AgentSecConfig {
  version: number;
  ui: {
    language: string;
    theme: string;
    confirm_update: boolean;
    confirm_uninstall: boolean;
    confirm_disable: boolean;
  };
  scan: {
    cve_online: boolean;
  };
  agents: {
    hermes_home: string;
    openclaw_home: string;
    hermes_bin: string;
    openclaw_bin: string;
  };
  dev: {
    debug: boolean;
    engine_dir: string;
    python: string;
  };
}

const DEFAULT_CONFIG: AgentSecConfig = {
  version: 1,
  ui: {
    language: "zh",
    theme: "glass",
    confirm_update: true,
    confirm_uninstall: true,
    confirm_disable: true,
  },
  scan: {
    cve_online: true,
  },
  agents: {
    hermes_home: "",
    openclaw_home: "",
    hermes_bin: "",
    openclaw_bin: "",
  },
  dev: {
    debug: false,
    engine_dir: "",
    python: "",
  },
};

function deepMerge<T extends Record<string, unknown>>(base: T, patch: Record<string, unknown>): T {
  const out = { ...base } as Record<string, unknown>;
  for (const [key, val] of Object.entries(patch)) {
    const cur = out[key];
    if (val && typeof val === "object" && !Array.isArray(val) && cur && typeof cur === "object") {
      out[key] = deepMerge(cur as Record<string, unknown>, val as Record<string, unknown>);
    } else {
      out[key] = val;
    }
  }
  return out as T;
}

/** 平台默认数据目录（未打包、无 AGENTSEC_DATA_DIR 时） */
export function platformDataDir(): string {
  if (process.env.AGENTSEC_DATA_DIR) return process.env.AGENTSEC_DATA_DIR;
  const home = os.homedir();
  if (process.platform === "win32") {
    const base = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(base, APP_DATA_DIR_NAME);
  }
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", APP_DATA_DIR_NAME);
  }
  const xdg = process.env.XDG_DATA_HOME;
  if (xdg) return path.join(xdg, APP_DATA_DIR_NAME);
  return path.join(home, ".local", "share", APP_DATA_DIR_NAME);
}

/** 有效数据目录：env > 打包态 userData > 平台默认 */
export function resolveDataDir(): string {
  if (process.env.AGENTSEC_DATA_DIR) return process.env.AGENTSEC_DATA_DIR;
  if (app.isPackaged) return app.getPath("userData");
  return platformDataDir();
}

export function configFilePath(dataDir?: string): string {
  return path.join(dataDir ?? resolveDataDir(), CONFIG_FILENAME);
}

function applyEnvOverrides(cfg: AgentSecConfig): AgentSecConfig {
  const out = structuredClone(cfg);
  if (process.env.AGENTSEC_CVE_OFFLINE) out.scan.cve_online = false;
  if (process.env.AGENTSEC_DEBUG === "1") out.dev.debug = true;
  if (process.env.AGENTSEC_ENGINE_DIR) out.dev.engine_dir = process.env.AGENTSEC_ENGINE_DIR;
  if (process.env.AGENTSEC_PYTHON) out.dev.python = process.env.AGENTSEC_PYTHON;
  if (process.env.AGENTSEC_HERMES_HOME) out.agents.hermes_home = process.env.AGENTSEC_HERMES_HOME;
  if (process.env.AGENTSEC_OPENCLAW_HOME) out.agents.openclaw_home = process.env.AGENTSEC_OPENCLAW_HOME;
  if (process.env.AGENTSEC_HERMES_BIN) out.agents.hermes_bin = process.env.AGENTSEC_HERMES_BIN;
  if (process.env.AGENTSEC_OPENCLAW_BIN) out.agents.openclaw_bin = process.env.AGENTSEC_OPENCLAW_BIN;
  return out;
}

export function loadConfigFile(dataDir?: string): AgentSecConfig {
  const dir = dataDir ?? resolveDataDir();
  mkdirSync(dir, { recursive: true });
  const file = configFilePath(dir);
  if (!existsSync(file)) return applyEnvOverrides(structuredClone(DEFAULT_CONFIG));
  try {
    const parsed = JSON.parse(readFileSync(file, "utf-8")) as Partial<AgentSecConfig>;
    const merged = deepMerge(
      structuredClone(DEFAULT_CONFIG) as unknown as Record<string, unknown>,
      parsed as unknown as Record<string, unknown>
    ) as unknown as AgentSecConfig;
    merged.version = 1;
    return applyEnvOverrides(merged);
  } catch {
    return applyEnvOverrides(structuredClone(DEFAULT_CONFIG));
  }
}

export function isDebugEnabled(): boolean {
  return loadConfigFile().dev.debug;
}

export function engineDir(appRoot: string): string {
  const cfg = loadConfigFile();
  if (process.env.AGENTSEC_ENGINE_DIR) return process.env.AGENTSEC_ENGINE_DIR;
  if (cfg.dev.engine_dir) return cfg.dev.engine_dir;
  return path.join(appRoot, "..", "engine");
}

export function venvPythonPath(engineRoot: string): string {
  if (process.platform === "win32") {
    return path.join(engineRoot, ".venv", "Scripts", "python.exe");
  }
  return path.join(engineRoot, ".venv", "bin", "python");
}

export function resolvePython(engineRoot: string): string {
  const cfg = loadConfigFile();
  if (process.env.AGENTSEC_PYTHON) return process.env.AGENTSEC_PYTHON;
  if (cfg.dev.python) return cfg.dev.python;
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
  env.AGENTSEC_DATA_DIR = resolveDataDir();
  return env;
}

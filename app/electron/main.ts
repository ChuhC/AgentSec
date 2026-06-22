import { app, BrowserWindow, ipcMain } from "electron";
import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// dist-electron/ 在 app/ 下；引擎在 ../engine
const APP_ROOT = path.join(__dirname, "..");
const ENGINE_DIR =
  process.env.AGENTSEC_ENGINE_DIR || path.join(APP_ROOT, "..", "engine");

// pyATR 需 Python ≥ 3.10：优先使用 engine/.venv，其次环境变量，最后系统 python3
function resolvePython(): string {
  if (process.env.AGENTSEC_PYTHON) return process.env.AGENTSEC_PYTHON;
  const venv = path.join(ENGINE_DIR, ".venv", "bin", "python");
  if (existsSync(venv)) return venv;
  return "python3";
}

// 引擎启动方式：
//  - 打包态（dmg）：spawn PyInstaller 冻结的二进制（无需系统 Python）
//  - 开发态：python -m agentsec_engine（用 engine/.venv）
function resolveEngine(): { cmd: string; args: string[]; cwd: string } {
  if (app.isPackaged) {
    const dir = path.join(process.resourcesPath, "engine");
    return { cmd: path.join(dir, "agentsec-engine"), args: [], cwd: dir };
  }
  return { cmd: resolvePython(), args: ["-m", "agentsec_engine"], cwd: ENGINE_DIR };
}

let win: BrowserWindow | null = null;
let engine: ChildProcessWithoutNullStreams | null = null;
/** 每次 start/stop 递增，避免旧子进程 exit 回调误清空新 engine 引用。 */
let engineGeneration = 0;
let pageLoadCount = 0;
let scanInProgress = false;
let deferredEngineRestart = false;

// IPC 请求 id → resolve
const pending = new Map<number, (v: any) => void>();
let nextId = 1;
let stdoutBuf = "";
const pendingEvents: { event: string; data: any }[] = [];

const DEBUG =
  process.env.AGENTSEC_DEBUG === "1" || !!process.env["VITE_DEV_SERVER_URL"];

function log(...args: unknown[]) {
  if (DEBUG) console.log("[main]", ...args);
}

function emitEngineEvent(payload: { event: string; data: any }) {
  const { event } = payload;
  if (event === "progress") {
    scanInProgress = true;
  } else if (
    event === "scan.completed" ||
    event === "scan.cancelled" ||
    event === "scan.error"
  ) {
    finishScanActivity();
  }
  if (event === "progress" && DEBUG) {
    log("engine-event progress", payload.data?.percent, payload.data?.label);
  } else if (payload.event !== "progress" && DEBUG) {
    log("engine-event", payload.event);
  }
  if (win && !win.isDestroyed()) {
    win.webContents.send("engine-event", payload);
  } else {
    pendingEvents.push(payload);
  }
}

function flushPendingEvents() {
  if (!win || win.isDestroyed()) return;
  log("flush pending events:", pendingEvents.length);
  while (pendingEvents.length) {
    win.webContents.send("engine-event", pendingEvents.shift()!);
  }
}

function stopEngine() {
  if (!engine) return;
  engineGeneration += 1;
  try {
    engine.stdin.end();
  } catch {
    /* ignore */
  }
  engine.kill();
  engine = null;
  for (const [id, resolve] of pending.entries()) {
    pending.delete(id);
    resolve({ error: { message: "engine stopped" } });
  }
}

/** 开发态页面热更新不会重启 Python 子进程，需显式 reload 引擎以加载新 IPC。 */
function restartEngine() {
  if (scanInProgress) {
    deferredEngineRestart = true;
    log("defer engine restart: scan in progress");
    return;
  }
  stopEngine();
  stdoutBuf = "";
  startEngine();
}

function finishScanActivity() {
  scanInProgress = false;
  if (deferredEngineRestart) {
    deferredEngineRestart = false;
    restartEngine();
  }
}

function enginePathEnv(): string {
  const home = os.homedir();
  const extra = [
    path.join(home, ".npm-global", "bin"),
    path.join(home, ".local", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
  ];
  return [...extra, process.env.PATH ?? ""].filter(Boolean).join(path.delimiter);
}

function startEngine() {
  const gen = ++engineGeneration;
  const { cmd, args, cwd } = resolveEngine();
  log("start engine:", cmd, args.join(" "), "cwd=", cwd);
  const child = spawn(cmd, args, {
    cwd,
    env: { ...process.env, PYTHONUNBUFFERED: "1", PATH: enginePathEnv() },
  });
  engine = child;

  child.stdout.setEncoding("utf-8");
  child.stdout.on("data", (chunk: string) => {
    stdoutBuf += chunk;
    let idx: number;
    while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
      const line = stdoutBuf.slice(0, idx).trim();
      stdoutBuf = stdoutBuf.slice(idx + 1);
      if (line) handleEngineLine(line);
    }
  });

  child.stderr.setEncoding("utf-8");
  child.stderr.on("data", (chunk: string) => {
    // 引擎日志走 stderr，dev 时在运行 npm run dev 的终端里可见
    process.stderr.write("[py] " + chunk);
  });

  child.on("exit", (code) => {
    if (gen !== engineGeneration) return;
    console.error("[main] engine exited:", code);
    engine = null;
    const wasScanning = scanInProgress;
    finishScanActivity();
    if (win && !win.isDestroyed()) {
      win.webContents.send("engine-event", {
        event: "engine.exited",
        data: { code, scanInProgress: wasScanning },
      });
    }
    setTimeout(() => {
      if (!engine) startEngine();
    }, 300);
  });

  // 引擎就绪探测
  setTimeout(() => {
    if (gen !== engineGeneration) return;
    engineRequest("ping", {})
      .then(() => log("engine ping ok"))
      .catch((e) => console.error("[main] engine ping failed:", e.message));
  }, 500);
}

function handleEngineLine(line: string) {
  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    console.error("[main] bad engine line:", line.slice(0, 120));
    return;
  }
  if (msg.event) {
    emitEngineEvent({ event: msg.event, data: msg.data });
    return;
  }
  if (typeof msg.id === "number" && pending.has(msg.id)) {
    const resolve = pending.get(msg.id)!;
    pending.delete(msg.id);
    resolve(msg);
  }
}

function engineRequest(method: string, params: any): Promise<any> {
  return new Promise((resolve, reject) => {
    if (!engine) {
      reject(new Error("engine not running"));
      return;
    }
    const id = nextId++;
    pending.set(id, (msg) => {
      if (msg.error) reject(new Error(msg.error.message || "engine error"));
      else resolve(msg.result);
    });
    engine.stdin.write(JSON.stringify({ id, method, params }) + "\n");
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 640,
    backgroundColor: "#0a0612",
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 16, y: 18 },
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const devUrl = process.env["VITE_DEV_SERVER_URL"];
  if (devUrl) {
    win.loadURL(devUrl);
    win.webContents.openDevTools({ mode: "detach" });
  } else {
    win.loadFile(path.join(APP_ROOT, "dist", "index.html"));
  }
  win.webContents.on("did-finish-load", () => {
    flushPendingEvents();
    pageLoadCount += 1;
    // 仅热更新重载时重启 Python；首次加载已在 whenReady 启动
    if (devUrl && pageLoadCount > 1) restartEngine();
  });
}

ipcMain.handle("engine-request", async (_e, method: string, params: any) => {
  return engineRequest(method, params);
});

app.whenReady().then(() => {
  startEngine();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopEngine();
  if (process.platform !== "darwin") app.quit();
});

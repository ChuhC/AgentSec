import { app, BrowserWindow, ipcMain } from "electron";
import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
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

// IPC 请求 id → resolve
const pending = new Map<number, (v: any) => void>();
let nextId = 1;
let stdoutBuf = "";
const pendingEvents: { event: string; data: any }[] = [];

function emitEngineEvent(payload: { event: string; data: any }) {
  if (win && !win.webContents.isLoading()) {
    win.webContents.send("engine-event", payload);
  } else {
    pendingEvents.push(payload);
  }
}

function flushPendingEvents() {
  if (!win) return;
  while (pendingEvents.length) {
    win.webContents.send("engine-event", pendingEvents.shift()!);
  }
}

function startEngine() {
  const { cmd, args, cwd } = resolveEngine();
  engine = spawn(cmd, args, {
    cwd,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });

  engine.stdout.setEncoding("utf-8");
  engine.stdout.on("data", (chunk: string) => {
    stdoutBuf += chunk;
    let idx: number;
    while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
      const line = stdoutBuf.slice(0, idx).trim();
      stdoutBuf = stdoutBuf.slice(idx + 1);
      if (line) handleEngineLine(line);
    }
  });

  engine.stderr.setEncoding("utf-8");
  engine.stderr.on("data", (chunk: string) => {
    process.stderr.write("[py] " + chunk);
  });

  engine.on("exit", (code) => {
    console.error("[main] engine exited:", code);
    engine = null;
  });
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
    width: 1024,
    height: 680,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: "#0a0612",
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 16, y: 18 },
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const devUrl = process.env["VITE_DEV_SERVER_URL"];
  if (devUrl) {
    win.loadURL(devUrl);
  } else {
    win.loadFile(path.join(APP_ROOT, "dist", "index.html"));
  }
  win.webContents.once("did-finish-load", flushPendingEvents);
}

ipcMain.handle("engine-request", async (_e, method: string, params: any) => {
  return engineRequest(method, params);
});

app.whenReady().then(() => {
  createWindow();
  startEngine();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  engine?.stdin.end();
  engine?.kill();
  if (process.platform !== "darwin") app.quit();
});

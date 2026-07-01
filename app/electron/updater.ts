import { createRequire } from "node:module";
import { app, BrowserWindow, ipcMain } from "electron";

// electron-updater is CJS; ESM main cannot use named imports from it at runtime.
const { autoUpdater } = createRequire(import.meta.url)("electron-updater") as {
  autoUpdater: import("electron-updater").AppUpdater;
};

export type UpdaterPhase =
  | "idle"
  | "checking"
  | "available"
  | "not-available"
  | "downloading"
  | "downloaded"
  | "error";

export interface UpdaterStatus {
  phase: UpdaterPhase;
  version?: string;
  releaseNotes?: string;
  percent?: number;
  message?: string;
}

let enabled = false;
let status: UpdaterStatus = { phase: "idle" };

function send(win: BrowserWindow | null, next: UpdaterStatus) {
  status = next;
  if (win && !win.isDestroyed()) {
    win.webContents.send("updater-event", next);
  }
}

function configureFeed() {
  if (process.platform === "darwin") {
    autoUpdater.setFeedURL({
      provider: "generic",
      url: "https://github.com/ChuhC/AgentSec/releases/latest/download",
      channel: `latest-${process.arch}`,
    });
    return;
  }
  if (process.platform === "win32") {
    autoUpdater.setFeedURL({
      provider: "github",
      owner: "ChuhC",
      repo: "AgentSec",
    });
  }
}

function registerUpdaterIpc(getWindow: () => BrowserWindow | null) {
  ipcMain.handle("updater-get-info", () => ({
    version: app.getVersion(),
    enabled,
    status,
  }));

  ipcMain.handle("updater-check", async () => {
    if (!enabled) {
      return { ok: false, error: "updater disabled" };
    }
    try {
      await autoUpdater.checkForUpdates();
      return { ok: true, status };
    } catch (e: any) {
      send(getWindow(), {
        phase: "error",
        message: e?.message || String(e),
      });
      return { ok: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle("updater-download", async () => {
    if (!enabled) return { ok: false, error: "updater disabled" };
    try {
      await autoUpdater.downloadUpdate();
      return { ok: true, status };
    } catch (e: any) {
      send(getWindow(), {
        phase: "error",
        message: e?.message || String(e),
      });
      return { ok: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle("updater-install", () => {
    if (!enabled) return { ok: false, error: "updater disabled" };
    autoUpdater.quitAndInstall();
    return { ok: true };
  });
}

export function initAutoUpdater(getWindow: () => BrowserWindow | null) {
  enabled =
    app.isPackaged &&
    (process.platform === "darwin" || process.platform === "win32");

  // Dev / unpackaged: handlers must exist so Settings does not throw on getInfo().
  registerUpdaterIpc(getWindow);
  if (!app.isPackaged || !enabled) return;

  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowDowngrade = false;
  configureFeed();

  autoUpdater.on("checking-for-update", () => {
    send(getWindow(), { phase: "checking" });
  });

  autoUpdater.on("update-available", (info) => {
    send(getWindow(), {
      phase: "available",
      version: info.version,
      releaseNotes:
        typeof info.releaseNotes === "string"
          ? info.releaseNotes
          : Array.isArray(info.releaseNotes)
            ? info.releaseNotes.map((n) => n.note).filter(Boolean).join("\n\n")
            : undefined,
    });
  });

  autoUpdater.on("update-not-available", () => {
    send(getWindow(), { phase: "not-available" });
  });

  autoUpdater.on("download-progress", (progress) => {
    send(getWindow(), {
      phase: "downloading",
      percent: Math.round(progress.percent),
    });
  });

  autoUpdater.on("update-downloaded", (info) => {
    send(getWindow(), {
      phase: "downloaded",
      version: info.version,
    });
  });

  autoUpdater.on("error", (err) => {
    send(getWindow(), {
      phase: "error",
      message: err?.message || String(err),
    });
  });

  setTimeout(() => {
    if (!enabled) return;
    autoUpdater.checkForUpdates().catch(() => {
      /* silent on startup */
    });
  }, 8000);
}

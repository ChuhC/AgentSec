import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ProgressData, ScanSnapshot } from "./types";

export type Route =
  | { name: "scan-home" }
  | { name: "scanning" }
  | { name: "results" }
  | { name: "exposure-detail"; findingId?: string }
  | { name: "cve-detail"; componentId?: string }
  | { name: "agent-list" }
  | { name: "agent-workbench"; agentId: string; tab?: string; focusSource?: string }
  | { name: "settings" };

export type ScanState = "idle" | "scanning" | "done" | "error";

export interface Settings {
  language: string;
  theme: string;
  defaultScope: string;
  confirmUpdate: boolean;
  confirmUninstall: boolean;
  confirmDisable: boolean;
}

interface AppState {
  route: Route;
  navigate: (r: Route) => void;
  snapshot: ScanSnapshot | null;
  scanState: ScanState;
  progress: ProgressData | null;
  scanError: string | null;
  settings: Settings;
  setSettings: (s: Partial<Settings>) => void;
  startScan: (scope: string, scopePath?: string) => Promise<void>;
  cancelScan: () => Promise<void>;
  updateAsset: (id: string) => Promise<void>;
  disableAsset: (id: string) => Promise<void>;
  enableAsset: (id: string) => Promise<void>;
  uninstallAsset: (id: string) => Promise<void>;
  lastError: string | null;
  clearError: () => void;
}

const Ctx = createContext<AppState | null>(null);

const DEFAULT_SETTINGS: Settings = {
  language: "简体中文",
  theme: "暗紫毛玻璃",
  defaultScope: "本机全部",
  confirmUpdate: true,
  confirmUninstall: true,
  confirmDisable: true,
};

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [route, setRoute] = useState<Route>({ name: "scan-home" });
  const [snapshot, setSnapshot] = useState<ScanSnapshot | null>(null);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [settings, setSettingsState] = useState<Settings>(DEFAULT_SETTINGS);
  const navAfterScan = useRef(false);
  const snapshotRef = useRef<ScanSnapshot | null>(null);
  snapshotRef.current = snapshot;

  const navigate = useCallback((r: Route) => setRoute(r), []);
  const setSettings = useCallback(
    (s: Partial<Settings>) => setSettingsState((prev) => ({ ...prev, ...s })),
    []
  );
  const clearError = useCallback(() => setLastError(null), []);

  // 启动时读取上次快照（NF-D1：重启可查看）
  useEffect(() => {
    window.agentsec
      ?.request("snapshot.get")
      .then((res) => {
        if (res?.snapshot) {
          setSnapshot(res.snapshot);
          setScanState("done");
        }
      })
      .catch(() => {});
  }, []);

  // 订阅引擎事件（只注册一次；勿依赖 snapshot，避免扫描中途重绑导致丢事件）
  useEffect(() => {
    let off: (() => void) | undefined;
    let timer: ReturnType<typeof setInterval> | undefined;

    const bind = () => {
      if (!window.agentsec) return false;
      off = window.agentsec.onEvent(({ event, data }) => {
        if (event === "progress") {
          setProgress(data as ProgressData);
        } else if (event === "scan.completed") {
          setSnapshot(data.snapshot);
          setScanState("done");
          setProgress(null);
          if (navAfterScan.current) {
            navAfterScan.current = false;
            setRoute({ name: "results" });
          }
        } else if (event === "scan.cancelled") {
          setProgress(null);
          const hasSnap = !!snapshotRef.current;
          setScanState(hasSnap ? "done" : "idle");
          setRoute(hasSnap ? { name: "results" } : { name: "scan-home" });
        } else if (event === "scan.error") {
          setScanState("error");
          setScanError(data.message || "扫描失败");
          setProgress(null);
        }
      });
      return true;
    };

    if (!bind()) {
      timer = setInterval(() => {
        if (bind()) clearInterval(timer);
      }, 50);
    }

    return () => {
      if (timer) clearInterval(timer);
      off?.();
    };
  }, []);

  const startScan = useCallback(async (scope: string, scopePath?: string) => {
    setScanError(null);
    setProgress(null);
    setScanState("scanning");
    navAfterScan.current = true;
    setRoute({ name: "scanning" });
    try {
      await window.agentsec.request("scan.start", { scope, scopePath });
    } catch (e: any) {
      setScanState("error");
      setScanError(e?.message || "无法启动扫描");
    }
  }, []);

  const cancelScan = useCallback(async () => {
    try {
      await window.agentsec.request("scan.cancel");
    } catch {
      /* ignore */
    }
  }, []);

  const doAssetOp = useCallback(
    async (method: string, id: string) => {
      try {
        const res = await window.agentsec.request(method, { assetId: id });
        if (res?.snapshot) setSnapshot(res.snapshot);
      } catch (e: any) {
        setLastError(e?.message || "操作失败");
      }
    },
    []
  );

  const value: AppState = useMemo(
    () => ({
      route,
      navigate,
      snapshot,
      scanState,
      progress,
      scanError,
      settings,
      setSettings,
      startScan,
      cancelScan,
      updateAsset: (id) => doAssetOp("asset.update", id),
      disableAsset: (id) => doAssetOp("asset.disable", id),
      enableAsset: (id) => doAssetOp("asset.enable", id),
      uninstallAsset: (id) => doAssetOp("asset.uninstall", id),
      lastError,
      clearError,
    }),
    [route, snapshot, scanState, progress, scanError, settings, lastError]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used within AppProvider");
  return v;
}

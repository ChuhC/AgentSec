import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { AgentRuntime, ProgressData, ScanSnapshot, Severity } from "./types";

export type Route =
  | { name: "scan-home" }
  | { name: "scanning" }
  | { name: "results" }
  | {
      name: "threat-list";
      findingId?: string;
      severity?: Severity;
      category?: string;
      agentId?: string;
    }
  | {
      name: "vuln-list";
      componentId?: string;
      severity?: Severity;
      agentId?: string;
    }
  | { name: "exposure-detail"; findingId?: string }
  | { name: "cve-detail"; componentId?: string }
  | { name: "agent-list" }
  | { name: "agent-workbench"; agentId: string; tab?: string; focusSource?: string }
  | { name: "settings" };

export type ScanState = "idle" | "scanning" | "cancelling" | "done" | "error";

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
  refreshAgentAssets: (agentId: string) => Promise<void>;
  fetchAgentRuntime: (agentId: string) => Promise<AgentRuntime | null>;
  ignoreThreat: (findingKey: string) => Promise<void>;
  unignoreThreat: (findingKey: string) => Promise<void>;
  readFile: (path: string) => Promise<{ path: string; content: string; truncated: boolean }>;
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
        if (import.meta.env.DEV && event === "progress") {
          console.log("[ui] progress", data?.percent, data?.label);
        }
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
      setScanState("cancelling");
      await window.agentsec.request("scan.cancel");
    } catch (e: any) {
      setScanState("scanning");
      setLastError(e?.message || "取消扫描失败");
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

  const refreshAgentAssets = useCallback(async (agentId: string) => {
    try {
      const res = await window.agentsec.request("agent.refresh", { agentId });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || "刷新资产失败");
    }
  }, []);

  const fetchAgentRuntime = useCallback(async (agentId: string) => {
    try {
      const res = await window.agentsec.request("agent.runtime.get", { agentId });
      return (res?.runtime as AgentRuntime) ?? null;
    } catch (e: any) {
      setLastError(e?.message || "获取资源占用失败");
      return null;
    }
  }, []);

  const ignoreThreat = useCallback(async (findingKey: string) => {
    try {
      const res = await window.agentsec.request("threat.ignore", { findingKey });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || "忽略威胁失败");
    }
  }, []);

  const unignoreThreat = useCallback(async (findingKey: string) => {
    try {
      const res = await window.agentsec.request("threat.unignore", { findingKey });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || "取消忽略失败");
    }
  }, []);

  const readFile = useCallback(async (path: string) => {
    try {
      const res = await window.agentsec.request("file.read", { path });
      return res as { path: string; content: string; truncated: boolean };
    } catch (e: any) {
      setLastError(e?.message || "读取文件失败");
      throw e;
    }
  }, []);

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
      refreshAgentAssets,
      fetchAgentRuntime,
      ignoreThreat,
      unignoreThreat,
      readFile,
      lastError,
      clearError,
    }),
    [route, snapshot, scanState, progress, scanError, settings, lastError, refreshAgentAssets, fetchAgentRuntime, ignoreThreat, unignoreThreat, readFile]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used within AppProvider");
  return v;
}

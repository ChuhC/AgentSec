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
import {
  buildLocaleLayer,
  createT,
  localeFromSetting,
  themeFromSetting,
  type Locale,
  type LocaleDataLayer,
} from "./i18n";
import { applyTheme } from "./theme";
import { readScreenshotBootstrap } from "./screenshotBootstrap";
import {
  patchFromLegacySettings,
  patchFromSettings,
  settingsFromConfig,
  type ConfigurableSettings,
} from "./configBridge";

const screenshotBoot = readScreenshotBootstrap();

export type ScanScope = "all" | "custom";

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

/** 扫描菜单应跳转的路由：进行中时始终回到进度页。 */
export function resolveScanRoute(
  snapshot: ScanSnapshot | null,
  scanState: ScanState
): Route {
  if (scanState === "scanning" || scanState === "cancelling") {
    return { name: "scanning" };
  }
  if (snapshot) return { name: "results" };
  return { name: "scan-home" };
}

export type Settings = ConfigurableSettings;

interface AppState {
  route: Route;
  navigate: (r: Route) => void;
  snapshot: ScanSnapshot | null;
  scanState: ScanState;
  progress: ProgressData | null;
  scanError: string | null;
  settings: Settings;
  configPath: string | null;
  setSettings: (s: Partial<Settings>) => void;
  locale: Locale;
  t: ReturnType<typeof createT>;
  layer: LocaleDataLayer;
  startScan: (scope: ScanScope, scopePath?: string) => Promise<void>;
  cancelScan: () => Promise<void>;
  updateAsset: (id: string) => Promise<void>;
  disableAsset: (id: string) => Promise<void>;
  enableAsset: (id: string) => Promise<void>;
  uninstallAsset: (id: string) => Promise<void>;
  refreshAgentAssets: (agentId: string) => Promise<ScanSnapshot | null>;
  updateAgent: (agentId: string) => Promise<void>;
  fetchAgentRuntime: (agentId: string) => Promise<AgentRuntime | null>;
  ignoreThreat: (findingKey: string) => Promise<void>;
  unignoreThreat: (findingKey: string) => Promise<void>;
  readFile: (path: string) => Promise<{ path: string; content: string; truncated: boolean }>;
  lastError: string | null;
  clearError: () => void;
}

const Ctx = createContext<AppState | null>(null);

const SETTINGS_KEY = "agentsec.settings";

const DEFAULT_SETTINGS: Settings = {
  language: "zh",
  theme: "glass",
  confirmUpdate: true,
  confirmUninstall: true,
  confirmDisable: true,
  cveOnline: true,
};

function bootstrapSettings(): Settings {
  const merged = { ...DEFAULT_SETTINGS, ...(screenshotBoot?.settings ?? {}) };
  return {
    ...merged,
    language: localeFromSetting(String(merged.language ?? "zh")),
    theme: themeFromSetting(String(merged.theme ?? "glass")),
    cveOnline: merged.cveOnline !== false,
  };
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [route, setRoute] = useState<Route>(screenshotBoot?.route ?? { name: "scan-home" });
  const [snapshot, setSnapshot] = useState<ScanSnapshot | null>(null);
  const [scanState, setScanState] = useState<ScanState>(
    screenshotBoot?.preloadSnapshot ? "done" : "idle"
  );
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [settings, setSettingsState] = useState<Settings>(bootstrapSettings);
  const [configPath, setConfigPath] = useState<string | null>(null);
  const locale = settings.language;
  const t = useMemo(() => createT(locale), [locale]);
  const layer = useMemo(() => buildLocaleLayer(locale, t), [locale, t]);
  const navAfterScan = useRef(false);
  const snapshotRef = useRef<ScanSnapshot | null>(null);
  const scanStateRef = useRef<ScanState>("idle");
  snapshotRef.current = snapshot;
  scanStateRef.current = scanState;

  const navigate = useCallback((r: Route) => setRoute(r), []);
  const setSettings = useCallback((s: Partial<Settings>) => {
    setSettingsState((prev) => {
      const next = { ...prev, ...s };
      const patch = patchFromSettings(s);
      if (Object.keys(patch).length) {
        window.agentsec
          ?.request("config.patch", { patch })
          .catch((e: any) => setLastError(e?.message || t("errors.configSaveFailed")));
      }
      return next;
    });
  }, [t]);

  useEffect(() => applyTheme(settings.theme), [settings.theme]);

  useEffect(() => {
    document.documentElement.lang = locale === "en" ? "en" : "zh-CN";
  }, [locale]);
  const clearError = useCallback(() => setLastError(null), []);

  // 从 config.json 加载设置（并迁移旧 localStorage）
  useEffect(() => {
    window.agentsec
      ?.request("config.get")
      .then(async (res) => {
        if (res?.path) setConfigPath(res.path as string);
        let next = settingsFromConfig((res?.config as Record<string, unknown>) ?? {});
        if (screenshotBoot?.settings) {
          const boot = screenshotBoot.settings as Partial<Settings>;
          next = {
            ...next,
            ...boot,
            language: localeFromSetting(String(boot.language ?? next.language)),
            theme: themeFromSetting(String(boot.theme ?? next.theme)),
          };
        }
        try {
          const raw = localStorage.getItem(SETTINGS_KEY);
          if (raw) {
            const legacy = JSON.parse(raw) as Record<string, unknown>;
            const legacyPatch = patchFromLegacySettings(legacy);
            if (Object.keys(legacyPatch).length) {
              const patched = await window.agentsec!.request("config.patch", { patch: legacyPatch });
              if (patched?.path) setConfigPath(patched.path as string);
              next = settingsFromConfig((patched?.config as Record<string, unknown>) ?? {});
            }
            localStorage.removeItem(SETTINGS_KEY);
          }
        } catch {
          /* ignore legacy parse errors */
        }
        setSettingsState(next);
      })
      .catch(() => {});
  }, []);

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
        } else if (event === "engine.exited") {
          setProgress(null);
          const st = scanStateRef.current;
          if (st === "scanning" || st === "cancelling") {
            const hasSnap = !!snapshotRef.current;
            setScanState(hasSnap ? "done" : "idle");
            setRoute(hasSnap ? { name: "results" } : { name: "scan-home" });
          }
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

  const startScan = useCallback(async (scope: ScanScope, scopePath?: string) => {
    setScanError(null);
    setProgress(null);
    setScanState("scanning");
    navAfterScan.current = true;
    setRoute({ name: "scanning" });
    try {
      await window.agentsec.request("scan.start", { scope, scopePath });
    } catch (e: any) {
      setScanState("error");
      setScanError(e?.message || t("errors.scanStartFailed"));
    }
  }, [t]);

  const cancelScan = useCallback(async () => {
    setScanState("cancelling");
    const fallback = window.setTimeout(() => {
      if (scanStateRef.current !== "cancelling") return;
      setProgress(null);
      const hasSnap = !!snapshotRef.current;
      setScanState(hasSnap ? "done" : "idle");
      setRoute(hasSnap ? { name: "results" } : { name: "scan-home" });
    }, 8000);
    try {
      await window.agentsec.request("scan.cancel");
    } catch (e: any) {
      window.clearTimeout(fallback);
      setScanState("scanning");
      setLastError(e?.message || t("errors.cancelFailed"));
    }
  }, [t]);

  const doAssetOp = useCallback(
    async (method: string, id: string) => {
      try {
        const res = await window.agentsec.request(method, { assetId: id });
        if (res?.snapshot) setSnapshot(res.snapshot);
      } catch (e: any) {
        setLastError(e?.message || t("errors.opFailed"));
      }
    },
    [t]
  );

  const refreshAgentAssets = useCallback(async (agentId: string): Promise<ScanSnapshot | null> => {
    try {
      const res = await window.agentsec.request("agent.refresh", {
        agentId,
        forceUpdateCheck: true,
      });
      if (res?.snapshot) {
        setSnapshot(res.snapshot);
        return res.snapshot as ScanSnapshot;
      }
      return null;
    } catch (e: any) {
      setLastError(e?.message || t("errors.refreshAssetsFailed"));
      return null;
    }
  }, [t]);

  const updateAgent = useCallback(async (agentId: string) => {
    try {
      const res = await window.agentsec.request("agent.update", { agentId });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || t("errors.updateAgentFailed"));
      throw e;
    }
  }, [t]);

  const fetchAgentRuntime = useCallback(async (agentId: string) => {
    try {
      const res = await window.agentsec.request("agent.runtime.get", { agentId });
      return (res?.runtime as AgentRuntime) ?? null;
    } catch (e: any) {
      setLastError(e?.message || t("errors.runtimeFailed"));
      return null;
    }
  }, [t]);

  const ignoreThreat = useCallback(async (findingKey: string) => {
    try {
      const res = await window.agentsec.request("threat.ignore", { findingKey });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || t("errors.ignoreFailed"));
    }
  }, []);

  const unignoreThreat = useCallback(async (findingKey: string) => {
    try {
      const res = await window.agentsec.request("threat.unignore", { findingKey });
      if (res?.snapshot) setSnapshot(res.snapshot);
    } catch (e: any) {
      setLastError(e?.message || t("errors.unignoreFailed"));
    }
  }, [t]);

  const readFile = useCallback(async (path: string) => {
    try {
      const res = await window.agentsec.request("file.read", { path });
      return res as { path: string; content: string; truncated: boolean };
    } catch (e: any) {
      setLastError(e?.message || t("errors.readFileFailed"));
      throw e;
    }
  }, [t]);

  const value: AppState = useMemo(
    () => ({
      route,
      navigate,
      snapshot,
      scanState,
      progress,
      scanError,
      settings,
      configPath,
      setSettings,
      locale,
      t,
      layer,
      startScan,
      cancelScan,
      updateAsset: (id) => doAssetOp("asset.update", id),
      disableAsset: (id) => doAssetOp("asset.disable", id),
      enableAsset: (id) => doAssetOp("asset.enable", id),
      uninstallAsset: (id) => doAssetOp("asset.uninstall", id),
      refreshAgentAssets,
      updateAgent,
      fetchAgentRuntime,
      ignoreThreat,
      unignoreThreat,
      readFile,
      lastError,
      clearError,
    }),
    [route, snapshot, scanState, progress, scanError, settings, configPath, locale, t, layer, lastError, refreshAgentAssets, updateAgent, fetchAgentRuntime, ignoreThreat, unignoreThreat, readFile]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used within AppProvider");
  return v;
}

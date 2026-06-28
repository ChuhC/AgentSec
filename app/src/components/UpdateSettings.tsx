import React, { useCallback, useEffect, useState } from "react";
import { useApp } from "../store";
import type { UpdaterStatus } from "../types";

export function UpdateSettings() {
  const { t } = useApp();
  const [enabled, setEnabled] = useState(false);
  const [appVersion, setAppVersion] = useState("—");
  const [status, setStatus] = useState<UpdaterStatus>({ phase: "idle" });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const bridge = window.agentsec?.updater;
    if (!bridge) return;
    bridge.getInfo().then((info) => {
      setEnabled(info.enabled);
      setAppVersion(info.version);
      setStatus(info.status ?? { phase: "idle" });
    });
    return bridge.onStatus((next) => setStatus(next));
  }, []);

  const statusText = useCallback(() => {
    switch (status.phase) {
      case "checking":
        return t("settings.updateChecking");
      case "available":
        return t("settings.updateAvailable", { version: status.version ?? "?" });
      case "not-available":
        return t("settings.updateLatest");
      case "downloading":
        return t("settings.updateDownloading", { percent: status.percent ?? 0 });
      case "downloaded":
        return t("settings.updateReady", { version: status.version ?? "?" });
      case "error":
        return status.message || t("settings.updateError");
      default:
        return t("settings.updateHint");
    }
  }, [status, t]);

  const onCheck = async () => {
    const bridge = window.agentsec?.updater;
    if (!bridge || busy) return;
    setBusy(true);
    try {
      await bridge.check();
    } finally {
      setBusy(false);
    }
  };

  const onDownload = async () => {
    const bridge = window.agentsec?.updater;
    if (!bridge || busy) return;
    setBusy(true);
    try {
      await bridge.download();
    } finally {
      setBusy(false);
    }
  };

  const onInstall = () => {
    window.agentsec?.updater?.install();
  };

  if (!enabled) {
    return (
      <InfoRow label={t("settings.update")} value={t("settings.updateDevOnly")} />
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <InfoRow label={t("settings.version")} value={appVersion} />
      <div className="row" style={{ alignItems: "flex-start" }}>
        <span className="muted" style={{ width: 110, fontSize: 13.5, flexShrink: 0 }}>
          {t("settings.update")}
        </span>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
          <span style={{ fontSize: 13.5 }}>{statusText()}</span>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className="btn btn-sm"
              disabled={busy || status.phase === "checking" || status.phase === "downloading"}
              onClick={onCheck}
            >
              {t("settings.updateCheck")}
            </button>
            {status.phase === "available" && (
              <button type="button" className="btn btn-sm btn-primary" disabled={busy} onClick={onDownload}>
                {t("settings.updateDownload")}
              </button>
            )}
            {status.phase === "downloaded" && (
              <button type="button" className="btn btn-sm btn-primary" onClick={onInstall}>
                {t("settings.updateInstall")}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="row">
      <span className="muted" style={{ width: 110, fontSize: 13.5, flexShrink: 0 }}>
        {label}
      </span>
      <span style={{ fontSize: 13.5 }}>{value}</span>
    </div>
  );
}

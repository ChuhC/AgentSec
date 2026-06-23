import React, { useEffect, useState } from "react";
import { useApp } from "../store";
import type { ScanScope } from "../store";
import {
  IconCube,
  IconFolder,
  IconLayers,
  IconMonitor,
  IconScan,
  LogoMark,
  IconChevron,
} from "../components/Icons";

function ScanPathModal({
  onClose,
  onConfirm,
}: {
  onClose: () => void;
  onConfirm: (scope: ScanScope, path?: string) => void;
}) {
  const { t } = useApp();
  const [mode, setMode] = useState<ScanScope>("all");
  const [path, setPath] = useState("");
  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{t("scanHome.modalTitle")}</div>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>
        <span className="tag" style={{ marginBottom: 16, display: "inline-block" }}>
          {t("scanHome.step1")}
        </span>
        <label className="radio-row" onClick={() => setMode("all")}>
          <span className={`radio ${mode === "all" ? "on" : ""}`} />
          {t("common.scope.all")}
        </label>
        <label className="radio-row" onClick={() => setMode("custom")}>
          <span className={`radio ${mode === "custom" ? "on" : ""}`} />
          {t("common.scope.custom")}
        </label>
        <div className="row" style={{ gap: 10, marginTop: 12 }}>
          <input
            className="text-input"
            placeholder={t("scanHome.pathPlaceholder")}
            value={path}
            disabled={mode === "all"}
            onChange={(e) => setPath(e.target.value)}
          />
          <button
            className="btn btn-sm"
            disabled={mode === "all"}
            onClick={() => setPath("/Users/me/agents")}
          >
            {t("scanHome.pickFolder")}
          </button>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            {t("common.action.cancel")}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => onConfirm(mode, mode === "custom" ? path : undefined)}
          >
            {t("common.action.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}

export function ScanHome() {
  const { startScan, snapshot, scanState, navigate, t } = useApp();
  const [modal, setModal] = useState(false);
  const last = snapshot?.meta.finished_at || "-";

  useEffect(() => {
    if (scanState === "scanning" || scanState === "cancelling") {
      navigate({ name: "scanning" });
    }
  }, [scanState, navigate]);

  return (
    <main className="main">
      <div
        className="glow-panel"
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: 32,
        }}
      >
        <LogoMark size={92} />
        <div style={{ fontSize: 34, fontWeight: 700, marginTop: 6 }}>AgentSec</div>
        <h1 style={{ fontSize: 30, fontWeight: 800, marginTop: 22 }}>
          {t("scanHome.hero")}
        </h1>

        <div className="row" style={{ gap: 48, marginTop: 40 }}>
          <ScopeTag
            icon={<IconMonitor size={22} />}
            title={t("scanHome.scopeBaseline")}
            sub={t("scanHome.scopeBaselineSub")}
          />
          <ScopeTag
            icon={<IconCube size={22} />}
            title={t("scanHome.scopeCve")}
            sub={t("scanHome.scopeCveSub")}
          />
          <ScopeTag
            icon={<IconLayers size={22} />}
            title={t("scanHome.scopeAssets")}
            sub={t("scanHome.scopeAssetsSub")}
          />
        </div>

        <div
          className="row"
          style={{ marginTop: 56, width: "100%", maxWidth: 760, gap: 24 }}
        >
          <span className="link" onClick={() => setModal(true)}>
            <IconFolder size={16} /> {t("scanHome.scanPath")} <IconChevron size={14} />
          </span>
          <div className="spacer" />
          <button
            className="btn btn-primary"
            style={{ padding: "16px 48px", fontSize: 16, borderRadius: 14 }}
            onClick={() => startScan("all")}
          >
            <span className="row" style={{ gap: 8 }}>
              <IconScan size={18} /> {t("scanHome.startScan")}
            </span>
          </button>
          <div className="spacer" />
          <div style={{ textAlign: "right" }}>
            <div className="dim" style={{ fontSize: 12 }}>
              {t("scanHome.lastScan")}
            </div>
            <div className="muted" style={{ fontSize: 13 }}>
              {last}
            </div>
          </div>
        </div>
      </div>

      {modal && (
        <ScanPathModal
          onClose={() => setModal(false)}
          onConfirm={(scope, path) => {
            setModal(false);
            startScan(scope, path);
          }}
        />
      )}
    </main>
  );
}

function ScopeTag({
  icon,
  title,
  sub,
}: {
  icon: React.ReactNode;
  title: string;
  sub: string;
}) {
  return (
    <div className="row" style={{ gap: 14 }}>
      <div
        className="row"
        style={{
          width: 46,
          height: 46,
          borderRadius: 12,
          background: "var(--purple-soft)",
          color: "var(--purple-2)",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
      <div>
        <div style={{ fontWeight: 700, fontSize: 15 }}>{title}</div>
        <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>
          {sub}
        </div>
      </div>
    </div>
  );
}

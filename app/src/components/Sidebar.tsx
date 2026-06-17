import React from "react";
import { useApp } from "../store";
import {
  IconAssets,
  IconCube,
  IconScan,
  IconSettings,
  IconShield,
  LogoMark,
} from "./Icons";

export function Sidebar() {
  const { route, navigate, snapshot, t } = useApp();
  const name = route.name;

  const isScan =
    name === "scan-home" || name === "scanning" || name === "results";
  const isThreat =
    name === "threat-list" || name === "exposure-detail";
  const isVuln = name === "vuln-list" || name === "cve-detail";
  const isAssets = name === "agent-list" || name === "agent-workbench";
  const isSettings = name === "settings";

  const goScan = () => {
    if (snapshot) navigate({ name: "results" });
    else navigate({ name: "scan-home" });
  };

  const goThreat = () => {
    if (!snapshot) return;
    navigate({ name: "threat-list" });
  };

  const goVuln = () => {
    if (!snapshot) return;
    navigate({ name: "vuln-list" });
  };

  return (
    <aside className="sidebar">
      <div className="brand">
        <LogoMark size={30} />
        <span className="name">AgentSec</span>
      </div>

      <nav className="nav">
        <div className={`nav-item ${isScan ? "active" : ""}`} onClick={goScan}>
          <IconScan className="icon" />
          <span>{t("sidebar.scan")}</span>
        </div>
        <div
          className={`nav-item ${isThreat ? "active" : ""}${!snapshot ? " disabled" : ""}`}
          onClick={goThreat}
          title={!snapshot ? t("sidebar.scanRequired") : undefined}
        >
          <IconShield className="icon" />
          <span>{t("sidebar.threats")}</span>
        </div>
        <div
          className={`nav-item ${isVuln ? "active" : ""}${!snapshot ? " disabled" : ""}`}
          onClick={goVuln}
          title={!snapshot ? t("sidebar.scanRequired") : undefined}
        >
          <IconCube className="icon" />
          <span>{t("sidebar.vulns")}</span>
        </div>
        <div
          className={`nav-item ${isAssets ? "active" : ""}`}
          onClick={() => navigate({ name: "agent-list" })}
        >
          <IconAssets className="icon" />
          <span>{t("sidebar.assets")}</span>
        </div>
      </nav>

      <div className="sidebar-foot">
        <div
          className={`nav-item ${isSettings ? "active" : ""}`}
          onClick={() => navigate({ name: "settings" })}
        >
          <IconSettings className="icon" />
          <span>{t("sidebar.settings")}</span>
        </div>
      </div>
    </aside>
  );
}

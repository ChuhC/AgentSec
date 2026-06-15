import React from "react";
import { useApp } from "../store";
import {
  IconAssets,
  IconScan,
  IconSettings,
  LogoMark,
} from "./Icons";

export function Sidebar() {
  const { route, navigate, snapshot } = useApp();
  const name = route.name;

  const isScan =
    name === "scan-home" ||
    name === "scanning" ||
    name === "results" ||
    name === "exposure-detail" ||
    name === "cve-detail";
  const isAssets = name === "agent-list" || name === "agent-workbench";
  const isSettings = name === "settings";

  const goScan = () => {
    if (snapshot) navigate({ name: "results" });
    else navigate({ name: "scan-home" });
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
          <span>安全扫描</span>
        </div>
        <div
          className={`nav-item ${isAssets ? "active" : ""}`}
          onClick={() => navigate({ name: "agent-list" })}
        >
          <IconAssets className="icon" />
          <span>资产管理</span>
        </div>
        <div
          className={`nav-item ${isSettings ? "active" : ""}`}
          onClick={() => navigate({ name: "settings" })}
        >
          <IconSettings className="icon" />
          <span>设置</span>
        </div>
      </nav>

      <div className="plan-badge">
        <div className="dot" />
        <div>
          <b>专业版</b>
          <div>有效期至 2025-12-31</div>
        </div>
      </div>
    </aside>
  );
}

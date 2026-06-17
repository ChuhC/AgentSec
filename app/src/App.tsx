import React from "react";
import { Sidebar } from "./components/Sidebar";
import { useApp } from "./store";
import { ScanHome } from "./pages/ScanHome";
import { Scanning } from "./pages/Scanning";
import { Results } from "./pages/Results";
import { ThreatList } from "./pages/ThreatList";
import { VulnList } from "./pages/VulnList";
import { AgentList } from "./pages/AgentList";
import { AgentWorkbench } from "./pages/AgentWorkbench";
import { Settings } from "./pages/Settings";

export function App() {
  const { route, lastError, clearError, t } = useApp();

  let page: React.ReactNode;
  switch (route.name) {
    case "scan-home":
      page = <ScanHome />;
      break;
    case "scanning":
      page = <Scanning />;
      break;
    case "results":
      page = <Results />;
      break;
    case "threat-list":
      page = (
        <ThreatList
          findingId={route.findingId}
          severity={route.severity}
          category={route.category}
          agentId={route.agentId}
        />
      );
      break;
    case "vuln-list":
      page = (
        <VulnList
          componentId={route.componentId}
          severity={route.severity}
          agentId={route.agentId}
        />
      );
      break;
    case "exposure-detail":
      page = <ThreatList findingId={route.findingId} />;
      break;
    case "cve-detail":
      page = <VulnList componentId={route.componentId} />;
      break;
    case "agent-list":
      page = <AgentList />;
      break;
    case "agent-workbench":
      page = (
        <AgentWorkbench
          agentId={route.agentId}
          initialTab={route.tab}
          focusSource={route.focusSource}
        />
      );
      break;
    case "settings":
      page = <Settings />;
      break;
    default:
      page = <ScanHome />;
  }

  return (
    <div className="app">
      <Sidebar />
      {page}
      {lastError && (
        <div className="toast" onClick={clearError}>
          {lastError}
          {t("common.toastDismiss")}
        </div>
      )}
    </div>
  );
}

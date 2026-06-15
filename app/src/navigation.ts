import type { ScanSnapshot, Severity } from "./types";
import type { Route } from "./store";

export function threatListRoute(
  snapshot: ScanSnapshot,
  opts?: { severity?: Severity; category?: string; findingId?: string; forceGlobal?: boolean }
): Route {
  if (!opts?.forceGlobal && snapshot.agents.length === 1) {
    return {
      name: "agent-workbench",
      agentId: snapshot.agents[0].id,
      tab: "威胁管理",
    };
  }
  return {
    name: "threat-list",
    severity: opts?.severity,
    category: opts?.category,
    findingId: opts?.findingId,
  };
}

export function vulnListRoute(
  snapshot: ScanSnapshot,
  opts?: { severity?: Severity; componentId?: string; forceGlobal?: boolean }
): Route {
  if (!opts?.forceGlobal && snapshot.agents.length === 1) {
    return {
      name: "agent-workbench",
      agentId: snapshot.agents[0].id,
      tab: "漏洞管理",
    };
  }
  return {
    name: "vuln-list",
    severity: opts?.severity,
    componentId: opts?.componentId,
  };
}

import type { ScanSnapshot, Severity } from "./types";
import type { Route } from "./store";

export function threatListRoute(
  _snapshot: ScanSnapshot,
  opts?: { severity?: Severity; category?: string; findingId?: string }
): Route {
  return {
    name: "threat-list",
    severity: opts?.severity,
    category: opts?.category,
    findingId: opts?.findingId,
  };
}

export function vulnListRoute(
  _snapshot: ScanSnapshot,
  opts?: { severity?: Severity; componentId?: string }
): Route {
  return {
    name: "vuln-list",
    severity: opts?.severity,
    componentId: opts?.componentId,
  };
}

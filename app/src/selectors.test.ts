import { describe, expect, it } from "vitest";
import { scanSecurityScore } from "./scanCompleteness";
import type { ScanSnapshot } from "./types";

function snapshot(
  scanStatus: "complete" | "partial" | "no_agents",
  cveStatus: "ok" | "partial" | "unavailable"
): ScanSnapshot {
  return {
    schema_version: 1,
    meta: {
      started_at: "",
      finished_at: "",
      duration_seconds: 1,
      scope: "all",
      scan_status: scanStatus,
      cve_status: cveStatus,
    },
    agents: [],
    assets: [],
    exposure_findings: [],
    cve_findings: [],
  };
}

describe("scanSecurityScore", () => {
  it("does not claim a score for partial scans", () => {
    expect(scanSecurityScore(snapshot("partial", "ok"))).toBeNull();
    expect(scanSecurityScore(snapshot("no_agents", "ok"))).toBeNull();
  });

  it("does not claim a score when CVE coverage is incomplete", () => {
    expect(scanSecurityScore(snapshot("complete", "partial"))).toBeNull();
    expect(scanSecurityScore(snapshot("complete", "unavailable"))).toBeNull();
  });

  it("scores complete scans", () => {
    expect(scanSecurityScore(snapshot("complete", "ok"))).toBe(100);
  });

  it("keeps legacy snapshots complete when scan_status is absent", () => {
    const legacy = snapshot("complete", "ok");
    delete legacy.meta.scan_status;
    expect(scanSecurityScore(legacy)).toBe(100);
  });

  it("deducts exposure and high CVE risk without dropping below the floor", () => {
    const risky = snapshot("complete", "ok");
    risky.exposure_findings = Array.from({ length: 30 }, (_, index) => ({
      id: `R-${index}`,
      title: "risk",
      severity: "high",
      category: "test",
      source: "skill",
      agent_ids: [],
      impact: "",
      evidence: "",
      recommendation: "",
      plain_explanation: "",
      location: "",
      locations: [],
      tags: [],
    }));
    risky.cve_findings = Array.from({ length: 2 }, (_, index) => ({
        id: `CVE-test-${index}`,
        component: "demo",
        component_type: "npm",
        current_version: "1.0.0",
        fixed_version: "2.0.0",
        severity: "high",
        agent_ids: [],
        cves: [{ cve_id: "CVE-test", severity: "high", cvss: 9, summary: "x" }],
        first_seen: "",
        upgrade_advice: "",
      }));
    expect(scanSecurityScore(risky)).toBe(15);
  });
});

import { cveCounts, exposureCounts } from "./selectors";
import { computeSecurityScore } from "./securityScore";
import type { ScanSnapshot } from "./types";

/** 扫描结果页 · 综合安全评分（0–100，威胁 + 高危 CVE）。 */
export function scanSecurityScore(snapshot: ScanSnapshot): number | null {
  if (
    (snapshot.meta.scan_status ?? "complete") !== "complete" ||
    snapshot.meta.cve_status !== "ok"
  ) {
    return null;
  }
  const exposure = exposureCounts(snapshot);
  const cve = cveCounts(snapshot);
  return computeSecurityScore(
    exposure.high,
    exposure.medium,
    exposure.low,
    cve.high
  );
}

import type {
  Asset,
  CVEFinding,
  ExposureFinding,
  ScanSnapshot,
  Severity,
} from "./types";

const SEV_WEIGHT: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  safe: 0,
};

export function exposureCounts(s: ScanSnapshot) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of s.exposure_findings) {
    if (f.severity in c) (c as any)[f.severity]++;
  }
  return c;
}

export function cveCounts(s: ScanSnapshot) {
  let high = 0,
    medium = 0,
    affected = 0;
  for (const c of s.cve_findings) {
    if (c.severity === "high") high++;
    else if (c.severity === "medium") medium++;
    if (c.cves.length > 0) affected++;
  }
  return { high, medium, affected };
}

export function assetCounts(s: ScanSnapshot) {
  return {
    agents: s.agents.length,
    mcp: s.assets.filter((a) => a.type === "mcp").length,
    skills: s.assets.filter((a) => a.type === "skill").length,
    knowledge: s.assets.filter((a) => a.type === "knowledge").length,
    updatable: s.assets.filter((a) => a.status === "updatable").length,
  };
}

function scope(agentIds: string[], totalAgents: number): string {
  if (agentIds.length >= totalAgents) return "本机全部";
  if (agentIds.length === 1) return "1 个 Agent";
  return `${agentIds.length} 个 Agent`;
}

export interface TopItem {
  key: string;
  title: string;
  riskType: string; // 暴露面 / 基线配置 / 组件漏洞
  riskTypeClass: string;
  impact: string;
  severity: Severity;
  isCve: boolean;
  when: string;
}

export function topItems(s: ScanSnapshot, limit = 3): TopItem[] {
  const total = s.agents.length;
  const items: TopItem[] = [];

  for (const f of s.exposure_findings) {
    const baseline = f.source === "agent_config" || f.source === "openclaw_audit";
    items.push({
      key: "e-" + f.id,
      title: f.title,
      riskType: baseline ? "基线配置" : "暴露面",
      riskTypeClass: baseline ? "tag" : "tag",
      impact: scope(f.agent_ids, total),
      severity: f.severity,
      isCve: false,
      when: s.meta.finished_at,
    });
  }
  for (const c of s.cve_findings) {
    if (!c.cves.length) continue;
    const top = c.cves[0];
    items.push({
      key: "c-" + c.id,
      title: `${c.component} <= ${c.current_version} ${top.summary.split("，")[0]}（${top.cve_id}）`,
      riskType: "组件漏洞",
      riskTypeClass: "tag",
      impact: scope(c.agent_ids, total),
      severity: c.severity,
      isCve: true,
      when: s.meta.finished_at,
    });
  }

  items.sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity]);
  return items.slice(0, limit);
}

export function assetsByAgent(s: ScanSnapshot, agentId: string): Asset[] {
  return s.assets.filter((a) => a.agent_id === agentId);
}

export function exposureForAgent(
  s: ScanSnapshot,
  agentId: string
): ExposureFinding[] {
  return s.exposure_findings.filter((f) => f.agent_ids.includes(agentId));
}

export function cveForAgent(s: ScanSnapshot, agentId: string): CVEFinding[] {
  return s.cve_findings.filter((c) => c.agent_ids.includes(agentId));
}

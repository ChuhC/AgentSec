import type {
  Asset,
  CVEFinding,
  CVEItem,
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

/** 暴露面 finding 唯一键（Reporter 已按 source+rule_id 聚合） */
export function exposureFindingKey(f: ExposureFinding): string {
  return `${f.source}::${f.id}`;
}

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
    dependencies: s.assets.filter((a) => a.type === "dependency").length,
  };
}

/** CVE 详情页：全部已扫描依赖 + 关联 finding（无漏洞则为 undefined） */
export interface ScannedComponent {
  id: string;
  name: string;
  version: string;
  ecosystem: string | null;
  agentId: string;
  finding?: CVEFinding;
}

/** CVE 详情页：按 Agent + 组件名聚合（同 Agent 内同组件只一条） */
export interface VulnComponentRow {
  key: string;
  component: string;
  versionLabel: string;
  versions: string[];
  agentId: string;
  agentName: string;
  ecosystem: string;
  severity: Severity;
  cveCount: number;
  cves: CVEItem[];
  fixedVersion: string | null;
  firstSeen: string;
  upgradeAdvice: string;
}

export function vulnerableComponentRows(s: ScanSnapshot): VulnComponentRow[] {
  const agentName = (id: string) => s.agents.find((a) => a.id === id)?.name || id;
  const map = new Map<string, VulnComponentRow>();

  for (const f of s.cve_findings) {
    if (!f.cves.length) continue;
    for (const agentId of f.agent_ids) {
      const key = `${agentId}::${f.component}`;
      let row = map.get(key);
      if (!row) {
        row = {
          key,
          component: f.component,
          versionLabel: f.current_version,
          versions: [f.current_version],
          agentId,
          agentName: agentName(agentId),
          ecosystem: f.component_type,
          severity: f.severity,
          cveCount: f.cves.length,
          cves: [...f.cves],
          fixedVersion: f.fixed_version,
          firstSeen: f.first_seen,
          upgradeAdvice: f.upgrade_advice,
        };
        map.set(key, row);
        continue;
      }
      if (!row.versions.includes(f.current_version)) {
        row.versions.push(f.current_version);
      }
      for (const c of f.cves) {
        const hit = row.cves.find((x) => x.cve_id === c.cve_id);
        if (!hit) row.cves.push(c);
        else if (c.cvss > hit.cvss) {
          hit.cvss = c.cvss;
          hit.severity = c.severity;
          hit.summary = c.summary;
        }
      }
      row.cves.sort((a, b) => b.cvss - a.cvss);
      row.cveCount = row.cves.length;
      if (SEV_WEIGHT[f.severity] > SEV_WEIGHT[row.severity]) {
        row.severity = f.severity;
      }
      if (f.fixed_version && !row.fixedVersion) row.fixedVersion = f.fixed_version;
      if (f.first_seen && (!row.firstSeen || f.first_seen < row.firstSeen)) {
        row.firstSeen = f.first_seen;
      }
      row.versionLabel =
        row.versions.length === 1 ? row.versions[0] : `${row.versions.length} 个版本`;
    }
  }

  return [...map.values()].sort(
    (a, b) =>
      SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity] ||
      b.cveCount - a.cveCount ||
      a.component.localeCompare(b.component)
  );
}

/** @deprecated 组件漏洞页请用 vulnerableComponentRows（仅含风险项） */
export function scannedComponents(s: ScanSnapshot): ScannedComponent[] {
  const byKey = new Map(
    s.cve_findings.map((f) => [`${f.component}@${f.current_version}`, f])
  );
  return s.assets
    .filter((a) => a.type === "dependency")
    .map((a) => ({
      id: a.id,
      name: a.name,
      version: a.version || "—",
      ecosystem: a.ecosystem,
      agentId: a.agent_id,
      finding: byKey.get(`${a.name}@${a.version || ""}`),
    }))
    .sort((a, b) => {
      const aw = a.finding ? SEV_WEIGHT[a.finding.severity] : -1;
      const bw = b.finding ? SEV_WEIGHT[b.finding.severity] : -1;
      return bw - aw || a.name.localeCompare(b.name);
    });
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
      key: "e-" + exposureFindingKey(f),
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

/** Agent 工作台 · 暴露面风险类别分布 */
export function riskCategoryBreakdownForAgent(
  s: ScanSnapshot,
  agentId: string
): RiskCategoryRow[] {
  const map = new Map<string, { count: number; maxSeverity: Severity }>();
  for (const f of exposureForAgent(s, agentId)) {
    const cat = f.category || "其他";
    const prev = map.get(cat);
    if (!prev) {
      map.set(cat, { count: 1, maxSeverity: f.severity });
    } else {
      prev.count++;
      if (SEV_WEIGHT[f.severity] > SEV_WEIGHT[prev.maxSeverity]) {
        prev.maxSeverity = f.severity;
      }
    }
  }
  return [...map.entries()]
    .map(([category, v]) => ({ category, ...v }))
    .sort((a, b) => b.count - a.count || SEV_WEIGHT[b.maxSeverity] - SEV_WEIGHT[a.maxSeverity]);
}

/** 扫描结果页 · 综合安全评分（0–100，威胁 + 高危 CVE） */
export function scanSecurityScore(s: ScanSnapshot): number {
  const exp = exposureCounts(s);
  const cve = cveCounts(s);
  const cveHigh = s.meta.cve_status === "ok" ? cve.high : 0;
  return Math.max(
    0,
    Math.min(100, 100 - exp.high * 10 - exp.medium * 5 - exp.low * 2 - cveHigh * 8)
  );
}

/** Agent 工作台 · 整体安全评分（0–100） */
export function agentSecurityScore(s: ScanSnapshot, agentId: string): number {
  const exp = exposureForAgent(s, agentId);
  let high = 0;
  let med = 0;
  let low = 0;
  for (const f of exp) {
    if (f.severity === "high") high++;
    else if (f.severity === "medium") med++;
    else if (f.severity === "low") low++;
  }
  const cveHigh = cveForAgent(s, agentId).filter((c) => c.severity === "high").length;
  return Math.max(0, Math.min(100, 100 - high * 10 - med * 5 - low * 2 - cveHigh * 8));
}

export interface AgentOptimizationItem {
  id: string;
  title: string;
  severity: Severity;
  findingId?: string;
}

/** Agent 工作台 · 优化建议 */
export function agentOptimizationSuggestions(
  s: ScanSnapshot,
  agentId: string
): AgentOptimizationItem[] {
  const items: AgentOptimizationItem[] = [];
  const agent = s.agents.find((a) => a.id === agentId);
  const exp = exposureForAgent(s, agentId)
    .slice()
    .sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity]);

  for (const f of exp) {
    items.push({
      id: exposureFindingKey(f),
      title: f.title,
      severity: f.severity,
      findingId: f.id,
    });
  }

  if (agent?.permissions.some((p) => p.category === "Shell" && SEV_WEIGHT[p.severity] >= 2)) {
    items.push({
      id: "opt-shell",
      title: "Agent 拥有 Shell 执行权限",
      severity: "medium",
    });
  }

  const disabledMcp = s.assets.filter(
    (a) => a.agent_id === agentId && a.type === "mcp" && a.status === "disabled"
  ).length;
  if (disabledMcp > 0) {
    items.push({
      id: "opt-disabled-mcp",
      title: `${disabledMcp} 个 MCP 服务已禁用`,
      severity: "info",
    });
  }

  return items.slice(0, 6);
}

export function cveForAgent(s: ScanSnapshot, agentId: string): CVEFinding[] {
  return s.cve_findings.filter((c) => c.agent_ids.includes(agentId));
}

const PERM_RADAR_CATS = ["文件", "Shell", "网络", "工具", "知识库"] as const;
const PERM_SEV_W: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  safe: 0,
};

const AGENT_RADAR_COLORS: Record<string, { color: string; fill: string }> = {
  hermes: { color: "#a855f7", fill: "rgba(139,92,246,0.22)" },
  openclaw: { color: "#60a5fa", fill: "rgba(96,165,250,0.22)" },
};
const FALLBACK_RADAR_COLORS = [
  { color: "#34d399", fill: "rgba(52,211,153,0.2)" },
  { color: "#f59e0b", fill: "rgba(245,158,11,0.2)" },
  { color: "#f472b6", fill: "rgba(244,114,182,0.2)" },
];

export interface RiskCategoryRow {
  category: string;
  count: number;
  maxSeverity: Severity;
}

/** 暴露面风险按类别聚合（用于结果页分布图） */
export function riskCategoryBreakdown(s: ScanSnapshot): RiskCategoryRow[] {
  const map = new Map<string, { count: number; maxSeverity: Severity }>();
  for (const f of s.exposure_findings) {
    const cat = f.category || "其他";
    const prev = map.get(cat);
    if (!prev) {
      map.set(cat, { count: 1, maxSeverity: f.severity });
    } else {
      prev.count++;
      if (SEV_WEIGHT[f.severity] > SEV_WEIGHT[prev.maxSeverity]) {
        prev.maxSeverity = f.severity;
      }
    }
  }
  return [...map.entries()]
    .map(([category, v]) => ({ category, ...v }))
    .sort((a, b) => b.count - a.count || SEV_WEIGHT[b.maxSeverity] - SEV_WEIGHT[a.maxSeverity]);
}

export interface PendingAction {
  id: string;
  label: string;
  detail: string;
  count: number;
  tone: "warn" | "info" | "neutral";
}

/** 待处理动作摘要 */
export function pendingActions(s: ScanSnapshot): PendingAction[] {
  const exp = exposureCounts(s);
  const cve = cveCounts(s);
  const updatable = s.assets.filter((a) => a.status === "updatable");
  const disabledSkills = s.assets.filter((a) => a.type === "skill" && a.status === "disabled");
  const disabledMcp = s.assets.filter((a) => a.type === "mcp" && a.status === "disabled");

  const items: PendingAction[] = [];

  if (exp.high > 0) {
    items.push({
      id: "threat-high",
      label: "威胁高危待处理",
      detail: "安全规则与暴露面发现",
      count: exp.high,
      tone: "warn",
    });
  }
  if (s.meta.cve_status === "ok" && (cve.affected > 0 || cve.high > 0)) {
    items.push({
      id: "cve-vuln",
      label: "组件漏洞待处理",
      detail: `${cve.affected} 个组件含已知 CVE`,
      count: cve.affected > 0 ? cve.affected : cve.high,
      tone: "warn",
    });
  }
  if (updatable.length > 0) {
    items.push({
      id: "updatable",
      label: "组件可更新",
      detail: "建议更新到最新版本以降低 CVE 风险",
      count: updatable.length,
      tone: "info",
    });
  }
  if (disabledSkills.length > 0) {
    items.push({
      id: "disabled-skills",
      label: "Skill 已禁用",
      detail: "可在 Agent 工作台查看或重新启用",
      count: disabledSkills.length,
      tone: "neutral",
    });
  }
  if (disabledMcp.length > 0) {
    items.push({
      id: "disabled-mcp",
      label: "MCP 已禁用",
      detail: "可在 Agent 工作台查看或重新启用",
      count: disabledMcp.length,
      tone: "neutral",
    });
  }
  if (exp.medium > 0) {
    items.push({
      id: "threat-medium",
      label: "威胁中危待处理",
      detail: "建议按优先级逐步核查",
      count: exp.medium,
      tone: "info",
    });
  }
  return items;
}

function permissionScores(s: ScanSnapshot, agentId: string): number[] {
  const agent = s.agents.find((a) => a.id === agentId);
  if (!agent) return PERM_RADAR_CATS.map(() => 0);
  const assets = assetsByAgent(s, agentId);
  const perms = [...agent.permissions, ...assets.flatMap((a) => a.permissions)];
  return PERM_RADAR_CATS.map((cat) => {
    const inCat = perms.filter((p) => p.category === cat);
    const max = inCat.reduce((m, p) => Math.max(m, PERM_SEV_W[p.severity]), 0);
    return max / 3;
  });
}

/** 全机各 Agent 权限雷达数据 */
export function agentPermissionRadars(s: ScanSnapshot) {
  const axes = PERM_RADAR_CATS.map((label) => ({ label, score: 0 }));
  let fallback = 0;
  const series = s.agents.map((agent) => {
    const palette =
      AGENT_RADAR_COLORS[agent.kind] ||
      FALLBACK_RADAR_COLORS[fallback++ % FALLBACK_RADAR_COLORS.length];
    return {
      name: agent.name,
      agentId: agent.id,
      color: palette.color,
      fill: palette.fill,
      scores: permissionScores(s, agent.id),
    };
  });
  return { axes, series };
}

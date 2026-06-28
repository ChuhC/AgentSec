import type {
  Agent,
  Asset,
  AssetTypeT,
  CVEFinding,
  CVEItem,
  ExposureFinding,
  PermissionEntry,
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

/** 默认加白：~/.hermes/skills/red-teaming（red-teaming 样例技能） */
const WHITELIST_PATH_SUFFIX = "/.hermes/skills/red-teaming";

function threatLocationPath(loc: string): string {
  const raw = loc.trim();
  if (raw.startsWith("/") || raw.startsWith("~")) {
    return raw.replace(/:\d+$/, "");
  }
  return raw.split(":")[0];
}

function threatLocationLine(loc: string): number | undefined {
  const raw = loc.trim();
  if (raw.startsWith("/") || raw.startsWith("~")) {
    const m = raw.match(/:(\d+)$/);
    return m ? Number(m[1]) : undefined;
  }
  const parts = raw.split(":");
  if (parts.length >= 2) {
    const n = Number(parts[parts.length - 1]);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

export { threatLocationPath, threatLocationLine };

export function isWhitelistedThreatPath(path: string): boolean {
  const norm = threatLocationPath(path).replace(/\\/g, "/");
  return (
    norm.endsWith(WHITELIST_PATH_SUFFIX) ||
    norm.includes(`${WHITELIST_PATH_SUFFIX}/`)
  );
}

export function isThreatPathWhitelisted(f: ExposureFinding): boolean {
  const locs = f.locations?.length ? f.locations : f.location ? [f.location] : [];
  if (!locs.length) return false;
  return locs.every(isWhitelistedThreatPath);
}

export function isThreatManuallyIgnored(s: ScanSnapshot, f: ExposureFinding): boolean {
  return (s.ignored_threat_keys ?? []).includes(exposureFindingKey(f));
}

export function isThreatIgnored(s: ScanSnapshot, f: ExposureFinding): boolean {
  return isThreatPathWhitelisted(f) || isThreatManuallyIgnored(s, f);
}

export function effectiveThreatSeverity(s: ScanSnapshot, f: ExposureFinding): Severity {
  return isThreatIgnored(s, f) ? "safe" : f.severity;
}

/** 未忽略的威胁数量（可选限定 Agent） */
export function activeThreatCount(s: ScanSnapshot, agentId?: string): number {
  const list = agentId ? exposureForAgent(s, agentId) : s.exposure_findings;
  return list.filter((f) => !isThreatIgnored(s, f)).length;
}

export function exposureCounts(s: ScanSnapshot) {
  const c = { high: 0, medium: 0, low: 0, ignored: 0 };
  for (const f of s.exposure_findings) {
    if (isThreatIgnored(s, f)) {
      c.ignored++;
      continue;
    }
    if (f.severity === "high") c.high++;
    else if (f.severity === "medium") c.medium++;
    else if (f.severity === "low") c.low++;
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
    channels: s.assets.filter((a) => a.type === "channel").length,
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
          if (c.advisory_id) hit.advisory_id = c.advisory_id;
          if (c.reference_url) hit.reference_url = c.reference_url;
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
    if (isThreatIgnored(s, f)) continue;
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
    if (isThreatIgnored(s, f)) continue;
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

/** 综合安全评分（0–100）：递减扣分，避免多命中时直接归零 */
function computeSecurityScore(high: number, med: number, low: number, cveHigh: number): number {
  const threatDeduction = Math.min(75, high * 4 + med * 2 + low * 1);
  const cveDeduction = Math.min(25, cveHigh * 6);
  return Math.max(15, Math.min(100, 100 - threatDeduction - cveDeduction));
}

/** 扫描结果页 · 综合安全评分（0–100，威胁 + 高危 CVE） */
export function scanSecurityScore(s: ScanSnapshot): number {
  const exp = exposureCounts(s);
  const cve = cveCounts(s);
  const cveHigh = s.meta.cve_status === "ok" ? cve.high : 0;
  return computeSecurityScore(exp.high, exp.medium, exp.low, cveHigh);
}

/** Agent 工作台 · 整体安全评分（0–100） */
export function agentSecurityScore(s: ScanSnapshot, agentId: string): number {
  const exp = exposureForAgent(s, agentId);
  let high = 0;
  let med = 0;
  let low = 0;
  for (const f of exp) {
    if (isThreatIgnored(s, f)) continue;
    if (f.severity === "high") high++;
    else if (f.severity === "medium") med++;
    else if (f.severity === "low") low++;
  }
  const cveHigh = cveForAgent(s, agentId).filter((c) => c.severity === "high").length;
  return computeSecurityScore(high, med, low, cveHigh);
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
    if (isThreatIgnored(s, f)) continue;
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
  claude: { color: "#f97316", fill: "rgba(249,115,22,0.22)" },
};

export const AGENT_HUE: Record<string, string> = {
  hermes: "#a855f7",
  openclaw: "#60a5fa",
  claude: "#f97316",
};

export function agentHue(kind: string): string {
  return AGENT_HUE[kind] ?? AGENT_HUE.hermes;
}
const FALLBACK_RADAR_COLORS = [
  { color: "#34d399", fill: "rgba(52,211,153,0.2)" },
  { color: "#eab308", fill: "rgba(234,179,8,0.2)" },
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
    if (isThreatIgnored(s, f)) continue;
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

export type AssetSubTabKey = "MCP" | "Skills" | "Hooks" | "知识库" | "通道" | "依赖";

export interface PermissionSourceGroup {
  sourceLabel: string;
  source: string;
  permissions: PermissionEntry[];
  assetId?: string;
}

export type PermissionSectionKey = "agent_default" | "mcp" | "skill" | "hook" | "knowledge" | "channel";

export interface PermissionSection {
  key: PermissionSectionKey;
  subGroups: PermissionSourceGroup[];
}

const PERMISSION_SECTION_ORDER: PermissionSectionKey[] = [
  "agent_default",
  "mcp",
  "skill",
  "hook",
  "knowledge",
  "channel",
];

const ASSET_TYPE_TO_SECTION: Partial<Record<AssetTypeT, PermissionSectionKey>> = {
  mcp: "mcp",
  skill: "skill",
  hook: "hook",
  knowledge: "knowledge",
  channel: "channel",
};

const SECTION_SOURCE: Record<PermissionSectionKey, string> = {
  agent_default: "agent_config",
  mcp: "mcp",
  skill: "skill",
  hook: "agent_config",
  knowledge: "knowledge",
  channel: "channel",
};

function sortSubGroups(a: PermissionSourceGroup, b: PermissionSourceGroup): number {
  const maxA = a.permissions.reduce((m, p) => Math.max(m, SEV_WEIGHT[p.severity]), 0);
  const maxB = b.permissions.reduce((m, p) => Math.max(m, SEV_WEIGHT[p.severity]), 0);
  return maxB - maxA || a.sourceLabel.localeCompare(b.sourceLabel);
}

function dedupePermissions(perms: PermissionEntry[]): PermissionEntry[] {
  const seen = new Set<string>();
  const out: PermissionEntry[] = [];
  for (const p of perms) {
    if (seen.has(p.id)) continue;
    seen.add(p.id);
    out.push(p);
  }
  return out;
}

/** 权限 Tab：先按类型（Agent 默认 / MCP / Skill…）聚合，再按资产/组件分子组 */
export function groupPermissionsBySection(agent: Agent, assets: Asset[]): PermissionSection[] {
  const bucket = new Map<PermissionSectionKey, PermissionSourceGroup[]>();

  const push = (key: PermissionSectionKey, group: PermissionSourceGroup) => {
    const list = bucket.get(key) ?? [];
    list.push(group);
    bucket.set(key, list);
  };

  const agentPerms = dedupePermissions(agent.permissions);
  if (agentPerms.length) {
    push("agent_default", {
      sourceLabel: "Agent 默认",
      source: "agent_config",
      permissions: agentPerms,
    });
  }

  for (const asset of assets) {
    const perms = dedupePermissions(asset.permissions);
    if (!perms.length) continue;
    const sectionKey = ASSET_TYPE_TO_SECTION[asset.type];
    if (!sectionKey) continue;
    push(sectionKey, {
      sourceLabel: asset.name,
      source: SECTION_SOURCE[sectionKey],
      permissions: perms,
      assetId: asset.id,
    });
  }

  return PERMISSION_SECTION_ORDER.filter((key) => bucket.has(key)).map((key) => ({
    key,
    subGroups: (bucket.get(key) ?? []).sort(sortSubGroups),
  }));
}

export interface PermissionMatrixRow {
  key: string;
  sectionKey: PermissionSectionKey;
  group: PermissionSourceGroup;
}

/** 权限矩阵行：按 section 顺序展平为组件列表 */
export function flattenPermissionMatrixRows(sections: PermissionSection[]): PermissionMatrixRow[] {
  const out: PermissionMatrixRow[] = [];
  for (const section of sections) {
    for (const group of section.subGroups) {
      out.push({
        key: `${section.key}:${group.assetId ?? group.sourceLabel}`,
        sectionKey: section.key,
        group,
      });
    }
  }
  return out;
}

/** 某组件在指定类别下的权限（矩阵单元格） */
export function permissionsForMatrixCell(
  group: PermissionSourceGroup,
  category: string
): PermissionEntry[] {
  return group.permissions.filter((p) => p.category === category);
}

export function maxPermissionSeverity(perms: PermissionEntry[]): Severity | null {
  if (!perms.length) return null;
  let best: Severity = "low";
  let w = 0;
  for (const p of perms) {
    const pw = SEV_WEIGHT[p.severity] ?? 0;
    if (pw > w) {
      w = pw;
      best = p.severity;
    }
  }
  return best;
}

/** @deprecated 使用 groupPermissionsBySection */
export function groupPermissionsBySource(
  agent: Agent,
  assets: Asset[]
): PermissionSourceGroup[] {
  return groupPermissionsBySection(agent, assets).flatMap((s) => s.subGroups);
}

const SOURCE_TO_SUB_TAB: Record<string, AssetSubTabKey | null> = {
  mcp: "MCP",
  skill: "Skills",
  hook: "Hooks",
  knowledge: "知识库",
  channel: "通道",
  dependency: "依赖",
  agent_config: null,
};

const ASSET_TYPE_TO_SUB_TAB: Record<AssetTypeT, AssetSubTabKey> = {
  mcp: "MCP",
  skill: "Skills",
  hook: "Hooks",
  knowledge: "知识库",
  channel: "通道",
  dependency: "依赖",
};

function assetSubTabForType(type: AssetTypeT): AssetSubTabKey {
  return ASSET_TYPE_TO_SUB_TAB[type];
}

/** 解析「定位来源」目标：资产管理子 Tab + 资产 id */
export function resolvePermissionLocate(
  group: PermissionSourceGroup,
  assets: Asset[]
): { subTab: AssetSubTabKey; assetId: string } | null {
  if (group.source === "agent_config" || !group.assetId) return null;
  const subTab = SOURCE_TO_SUB_TAB[group.source];
  if (!subTab) return null;
  const hit = assets.find((a) => a.id === group.assetId);
  if (hit) return { subTab, assetId: hit.id };
  const label = group.sourceLabel.toLowerCase();
  const fuzzy = assets.find((a) => {
    if (assetSubTabForType(a.type) !== subTab) return false;
    const name = a.name.toLowerCase();
    return label.includes(name) || name.includes(label.replace(/ mcp$/, ""));
  });
  return fuzzy ? { subTab, assetId: fuzzy.id } : null;
}

function normThreatPath(path: string): string {
  return threatLocationPath(path).replace(/\\/g, "/").toLowerCase();
}

function skillMatchNeedles(asset: Asset): string[] {
  const needles = new Set<string>();
  if (asset.name) needles.add(asset.name.toLowerCase());
  if (asset.install_path) needles.add(normThreatPath(asset.install_path));
  if (asset.path) needles.add(normThreatPath(asset.path));
  if (asset.package_name) needles.add(asset.package_name.toLowerCase());
  const slug = asset.name
    .toLowerCase()
    .replace(/\s+skill$/i, "")
    .replace(/\s+/g, "-");
  if (slug.length >= 2) needles.add(slug);
  if (asset.install_path) {
    needles.add(`${normThreatPath(asset.install_path)}/skill.md`);
  }
  return [...needles].filter((n) => n.length >= 2);
}

function pathMatchesNeedle(path: string, needle: string): boolean {
  const norm = normThreatPath(path);
  return norm.includes(needle) || needle.includes(norm);
}

/** Skill 资产关联的暴露面 finding（按路径 / 证据 / 名称匹配） */
export function exposureFindingMatchesSkill(f: ExposureFinding, asset: Asset): boolean {
  const needles = skillMatchNeedles(asset);
  if (!needles.length) return false;

  const locs = f.locations?.length ? f.locations : f.location ? [f.location] : [];
  for (const loc of locs) {
    for (const n of needles) {
      if (pathMatchesNeedle(loc, n)) return true;
    }
    const normLoc = normThreatPath(loc);
    if (normLoc.endsWith("/skill.md") || normLoc.endsWith("/skill.md.disabled")) {
      const parts = normLoc.split("/");
      const dir = parts[parts.length - 2] ?? "";
      if (needles.some((n) => dir.includes(n) || n.includes(dir))) return true;
    }
  }

  const hay = `${f.evidence}\n${f.title}\n${f.impact}`.toLowerCase();
  for (const n of needles) {
    if (n.length >= 3 && hay.includes(n)) return true;
  }
  return false;
}

export function exposureFindingsForSkill(
  s: ScanSnapshot,
  agentId: string,
  asset: Asset
): ExposureFinding[] {
  return exposureForAgent(s, agentId)
    .filter((f) => exposureFindingMatchesSkill(f, asset))
    .sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity]);
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

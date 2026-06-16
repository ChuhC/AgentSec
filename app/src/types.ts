// 与 Python 引擎 models.py 对齐的前端类型。

export type Severity = "high" | "medium" | "low" | "safe" | "info";
export type AssetTypeT = "mcp" | "skill" | "knowledge" | "dependency";
export type AssetStatusT = "enabled" | "disabled" | "updatable";

export interface PermissionEntry {
  id: string;
  name: string;
  category: string; // 文件 / Shell / 网络 / 工具 / 知识库
  source: string;
  source_label: string;
  severity: Severity;
}

export interface Asset {
  id: string;
  agent_id: string;
  type: AssetTypeT;
  name: string;
  version: string | null;
  latest_version: string | null;
  status: AssetStatusT;
  purpose: string;
  source: string;
  ecosystem: string | null;
  manager: string | null;
  install_path: string | null;
  package_name: string | null;
  path: string | null;
  config_key: string | null;
  permissions: PermissionEntry[];
  can_update: boolean;
  can_disable: boolean;
  can_uninstall: boolean;
}

export interface Agent {
  id: string;
  name: string;
  kind: string;
  version: string;
  latest_version?: string | null;
  listen_ports?: string[];
  enabled: boolean;
  description: string;
  permissions: PermissionEntry[];
}

export interface AgentRuntime {
  agent_id: string;
  cpu_percent: number;
  memory_mb: number;
  memory_percent: number;
  disk_mb: number;
  disk_percent: number;
  listen_ports: string[];
  cpu_history: number[];
  memory_history: number[];
  disk_history: number[];
}

export interface ExposureFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  source: string;
  agent_ids: string[];
  impact: string;
  evidence: string;
  recommendation: string;
  plain_explanation: string;
  location: string;
  locations?: string[];
  tags: string[];
}

export interface CVEItem {
  cve_id: string;
  severity: Severity;
  cvss: number;
  summary: string;
}

export interface CVEFinding {
  id: string;
  component: string;
  component_type: string;
  current_version: string;
  fixed_version: string | null;
  severity: Severity;
  agent_ids: string[];
  first_seen: string;
  cves: CVEItem[];
  upgrade_advice: string;
}

export interface ScanMeta {
  started_at: string;
  finished_at: string;
  duration_seconds: number;
  scope: string;
  cve_status: "ok" | "unavailable";
  cve_scanned_count?: number;
}

export interface ScanSnapshot {
  schema_version: number;
  meta: ScanMeta;
  agents: Agent[];
  assets: Asset[];
  exposure_findings: ExposureFinding[];
  cve_findings: CVEFinding[];
  /** 用户手动忽略的威胁键（source::id） */
  ignored_threat_keys?: string[];
}

export interface ProgressData {
  type: string;
  stage: string;
  percent: number;
  label: string;
  counts: { agents?: number; mcp?: number; skills?: number };
}

declare global {
  interface Window {
    agentsec: {
      request: (method: string, params?: any) => Promise<any>;
      onEvent: (cb: (e: { event: string; data: any }) => void) => () => void;
    };
  }
}

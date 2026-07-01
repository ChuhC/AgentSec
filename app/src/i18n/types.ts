import type { Locale, MessageParams } from "./messages";

export type TFn = (path: string, params?: MessageParams) => string;

/** 界面通用枚举/文案；扫描引擎与用户文件内容经 layer 透传，不翻译。 */
export interface LocaleDataLayer {
  readonly locale: Locale;
  readonly t: TFn;

  scopeLabel(scope: string): string;
  listSeparator(): string;

  threatCategory(category: string): string;
  threatSource(source: string): string;
  threatTitle(ruleId: string, fallback: string, category: string): string;
  threatImpact(category: string, fallback: string): string;
  threatPlainExplanation(category: string, fallback: string): string;
  threatRecommendation(category: string, fallback: string): string;
  threatEvidence(evidence: string): string;

  agentDescription(description: string): string;
  agentUpdateDetail(detail: string): string;
  assetPurpose(purpose: string): string;
  cvePlainExplanation(summary: string): string;

  permissionCategory(category: string): string;
  permissionName(name: string): string;
  permissionSourceLabel(label: string): string;

  upgradeAdvice(advice: string, fixedVersion?: string | null): string;
  cveSummary(summary: string): string;

  pendingActionLabel(id: string): string;
  pendingActionDetail(id: string, count: number): string;
  optimizationTitle(item: { id: string; title: string }): string;
}

export type LocaleLayerFactory = (locale: Locale, t: TFn) => LocaleDataLayer;

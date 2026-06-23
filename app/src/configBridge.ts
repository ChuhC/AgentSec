import { localeFromSetting, themeFromSetting, type Locale } from "./i18n";
import type { ThemeSetting } from "./theme";

export interface ConfigurableSettings {
  language: Locale;
  theme: ThemeSetting;
  confirmUpdate: boolean;
  confirmUninstall: boolean;
  confirmDisable: boolean;
  cveOnline: boolean;
}

/** 引擎 config.json → 设置页 / store */
export function settingsFromConfig(config: {
  ui?: Record<string, unknown>;
  scan?: Record<string, unknown>;
}): ConfigurableSettings {
  const ui = config.ui ?? {};
  const scan = config.scan ?? {};
  return {
    language: localeFromSetting(String(ui.language ?? "zh")),
    theme: themeFromSetting(String(ui.theme ?? "glass")),
    confirmUpdate: ui.confirm_update !== false,
    confirmUninstall: ui.confirm_uninstall !== false,
    confirmDisable: ui.confirm_disable !== false,
    cveOnline: scan.cve_online !== false,
  };
}

/** 设置页局部更新 → config.patch */
export function patchFromSettings(partial: Partial<ConfigurableSettings>): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  const ui: Record<string, unknown> = {};
  if (partial.language !== undefined) ui.language = partial.language;
  if (partial.theme !== undefined) ui.theme = partial.theme;
  if (partial.confirmUpdate !== undefined) ui.confirm_update = partial.confirmUpdate;
  if (partial.confirmUninstall !== undefined) ui.confirm_uninstall = partial.confirmUninstall;
  if (partial.confirmDisable !== undefined) ui.confirm_disable = partial.confirmDisable;
  if (Object.keys(ui).length) patch.ui = ui;
  if (partial.cveOnline !== undefined) patch.scan = { cve_online: partial.cveOnline };
  return patch;
}

/** localStorage 旧键 → config.ui（一次性迁移） */
export function patchFromLegacySettings(raw: Record<string, unknown>): Record<string, unknown> {
  const ui: Record<string, unknown> = {};
  if (raw.language !== undefined) ui.language = raw.language;
  if (raw.theme !== undefined) ui.theme = raw.theme;
  if (raw.confirmUpdate !== undefined) ui.confirm_update = raw.confirmUpdate;
  if (raw.confirmUninstall !== undefined) ui.confirm_uninstall = raw.confirmUninstall;
  if (raw.confirmDisable !== undefined) ui.confirm_disable = raw.confirmDisable;
  return Object.keys(ui).length ? { ui } : {};
}

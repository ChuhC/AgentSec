import React from "react";
import { useApp } from "../store";
import type { Locale } from "../i18n";
import type { ThemeSetting } from "../theme";
import {
  IconSettings,
  IconScan,
  IconCube,
  IconAlert,
} from "../components/Icons";

export function Settings() {
  const { settings, setSettings, configPath, t } = useApp();

  return (
    <main className="main">
      <div className="page-title">{t("settings.title")}</div>

      <div style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 16 }}>
        <Group icon={<IconSettings size={18} />} title={t("settings.general")}>
          <SelectRow
            label={t("settings.language")}
            value={settings.language}
            options={[
              { value: "zh", label: t("settings.langZh") },
              { value: "en", label: t("settings.langEn") },
            ]}
            onChange={(v) => setSettings({ language: v as Locale })}
          />
          <SelectRow
            label={t("settings.theme")}
            value={settings.theme}
            options={[
              { value: "glass", label: t("settings.themeGlass") },
              { value: "light", label: t("settings.themeLight") },
              { value: "dark", label: t("settings.themeDark") },
              { value: "system", label: t("settings.themeSystem") },
            ]}
            onChange={(v) => setSettings({ theme: v as ThemeSetting })}
          />
        </Group>

        <Group icon={<IconScan size={18} />} title={t("settings.scan")}>
          <InfoRow label={t("settings.retention")} value={t("settings.retentionValue")} />
          <SwitchRow
            label={t("settings.cveOnline")}
            value={settings.cveOnline}
            onChange={(v) => setSettings({ cveOnline: v })}
          />
        </Group>

        <Group icon={<IconCube size={18} />} title={t("settings.assets")}>
          <SwitchRow
            label={t("settings.confirmUpdate")}
            value={settings.confirmUpdate}
            onChange={(v) => setSettings({ confirmUpdate: v })}
          />
          <SwitchRow
            label={t("settings.confirmUninstall")}
            value={settings.confirmUninstall}
            onChange={(v) => setSettings({ confirmUninstall: v })}
          />
          <SwitchRow
            label={t("settings.confirmDisable")}
            value={settings.confirmDisable}
            onChange={(v) => setSettings({ confirmDisable: v })}
          />
        </Group>

        <Group icon={<IconAlert size={18} />} title={t("settings.about")}>
          <InfoRow label={t("settings.version")} value="0.1.0" />
          <InfoRow label={t("settings.license")} value={t("settings.licenseValue")} />
          {configPath && (
            <InfoRow label={t("settings.configPath")} value={configPath} />
          )}
        </Group>
      </div>
    </main>
  );
}

function Group({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card" style={{ padding: "18px 22px" }}>
      <div className="row" style={{ gap: 24 }}>
        <div className="row" style={{ gap: 11, width: 150 }}>
          <span
            className="row"
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: "var(--purple-soft)",
              color: "var(--purple-2)",
              justifyContent: "center",
            }}
          >
            {icon}
          </span>
          <span style={{ fontWeight: 700 }}>{title}</span>
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 14 }}>
          {children}
        </div>
      </div>
    </div>
  );
}

function SelectRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  return (
    <div className="row">
      <span className="muted" style={{ width: 110, fontSize: 13.5 }}>
        {label}
      </span>
      <select
        className="select-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function SwitchRow({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="row">
      <span className="muted" style={{ width: 110, fontSize: 13.5 }}>
        {label}
      </span>
      <div className="spacer" />
      <div className={`switch ${value ? "on" : ""}`} onClick={() => onChange(!value)} />
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="row">
      <span className="muted" style={{ width: 110, fontSize: 13.5 }}>
        {label}
      </span>
      <span style={{ fontSize: 13.5 }}>{value}</span>
    </div>
  );
}

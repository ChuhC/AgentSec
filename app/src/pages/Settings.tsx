import React from "react";
import { useApp } from "../store";
import {
  IconSettings,
  IconScan,
  IconCube,
  IconAlert,
} from "../components/Icons";

export function Settings() {
  const { settings, setSettings } = useApp();

  return (
    <main className="main">
      <div className="page-title">设置</div>

      <div style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 16 }}>
        <Group icon={<IconSettings size={18} />} title="通用">
          <SelectRow
            label="语言"
            value={settings.language}
            options={["简体中文", "English"]}
            onChange={(v) => setSettings({ language: v })}
          />
          <SelectRow
            label="主题"
            value={settings.theme}
            options={["暗紫毛玻璃", "深色", "跟随系统"]}
            onChange={(v) => setSettings({ theme: v })}
          />
        </Group>

        <Group icon={<IconScan size={18} />} title="扫描">
          <SelectRow
            label="默认路径"
            value={settings.defaultScope}
            options={["本机全部", "自定义路径"]}
            onChange={(v) => setSettings({ defaultScope: v })}
          />
          <InfoRow label="结果保留" value="仅保留最近一次扫描" />
        </Group>

        <Group icon={<IconCube size={18} />} title="资产管理">
          <SwitchRow
            label="更新前确认"
            value={settings.confirmUpdate}
            onChange={(v) => setSettings({ confirmUpdate: v })}
          />
          <SwitchRow
            label="卸载前确认"
            value={settings.confirmUninstall}
            onChange={(v) => setSettings({ confirmUninstall: v })}
          />
          <SwitchRow
            label="禁用前确认"
            value={settings.confirmDisable}
            onChange={(v) => setSettings({ confirmDisable: v })}
          />
        </Group>

        <Group icon={<IconAlert size={18} />} title="关于">
          <InfoRow label="版本" value="0.1.0" />
          <InfoRow label="许可证" value="Apache-2.0" />
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
  options: string[];
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
          <option key={o} value={o}>
            {o}
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

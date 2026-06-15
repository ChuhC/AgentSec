import React from "react";

type P = { size?: number; className?: string; style?: React.CSSProperties };
const s = (n = 18) => ({ width: n, height: n });

export const LogoMark = ({ size = 30 }: P) => (
  <svg viewBox="0 0 32 32" style={s(size)} fill="none">
    <defs>
      <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#a855f7" />
        <stop offset="1" stopColor="#6d28d9" />
      </linearGradient>
    </defs>
    <path
      d="M16 2 L28 9 V23 L16 30 L4 23 V9 Z"
      fill="url(#lg)"
      opacity="0.25"
      stroke="url(#lg)"
      strokeWidth="1.5"
    />
    <path d="M16 9 L21 22 H18 L16.8 19 H15.2 L14 22 H11 Z" fill="#fff" />
  </svg>
);

export const IconScan = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
    <circle cx="12" cy="12" r="3.2" />
  </svg>
);

export const IconAssets = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <path d="M12 2 21 7v10l-9 5-9-5V7z" />
    <path d="M12 12 21 7M12 12v10M12 12 3 7" />
  </svg>
);

export const IconSettings = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-2.82 1.17V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 8 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 3.6 15H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6h.09A1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9h.6a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);

export const IconShield = ({ size = 18, className, style }: P) => (
  <svg viewBox="0 0 24 24" style={{ ...s(size), ...style }} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

export const IconCube = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <path d="M12 2 21 7v10l-9 5-9-5V7z" />
    <path d="M12 12 21 7M12 12v10M12 12 3 7" />
  </svg>
);

export const IconLayers = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <path d="M12 2 2 7l10 5 10-5z" />
    <path d="M2 12l10 5 10-5M2 17l10 5 10-5" />
  </svg>
);

export const IconChevron = ({ size = 16, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m9 6 6 6-6 6" />
  </svg>
);

export const IconArrowLeft = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 12H5M12 19l-7-7 7-7" />
  </svg>
);

export const IconFolder = ({ size = 16, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
  </svg>
);

export const IconClock = ({ size = 16, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </svg>
);

export const IconMonitor = ({ size = 16, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
    <rect x="3" y="4" width="18" height="12" rx="2" />
    <path d="M8 20h8M12 16v4" />
  </svg>
);

export const IconRefresh = ({ size = 16, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
    <path d="M21 3v5h-5" />
  </svg>
);

export const IconTerminal = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="m4 7 5 5-5 5M12 17h8" />
  </svg>
);

export const IconGlobe = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z" />
  </svg>
);

export const IconFile = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
  </svg>
);

export const IconBook = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
    <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z" />
  </svg>
);

export const IconBolt = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
    <path d="M13 2 3 14h7l-1 8 10-12h-7z" />
  </svg>
);

export const IconDatabase = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
    <ellipse cx="12" cy="5" rx="8" ry="3" />
    <path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3" />
  </svg>
);

export const IconExternal = ({ size = 14, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 3h6v6M10 14 21 3M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5" />
  </svg>
);

export const IconAlert = ({ size = 16, className, style }: P) => (
  <svg viewBox="0 0 24 24" style={{ ...s(size), ...style }} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v6M12 16.5v.5" />
  </svg>
);

export const IconCheck = ({ size = 16, className, style }: P) => (
  <svg viewBox="0 0 24 24" style={{ ...s(size), ...style }} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" />
    <path d="m8 12 3 3 5-6" />
  </svg>
);

export const IconPlug = ({ size = 18, className }: P) => (
  <svg viewBox="0 0 24 24" style={s(size)} className={className} fill="none"
    stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round">
    <path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5" />
  </svg>
);

export const IconHexAgent = ({ size = 40, hue = "#a855f7" }: P & { hue?: string }) => (
  <svg viewBox="0 0 48 48" style={s(size)} fill="none">
    <path d="M24 3 42 13.5v21L24 45 6 34.5v-21z" fill={hue} opacity="0.18"
      stroke={hue} strokeWidth="1.6" />
    <path d="M24 14 31 33h-4l-1.6-4.5h-2.8L21 33h-4z" fill={hue} />
  </svg>
);

import React from "react";

export interface RadarAxis {
  label: string;
  score: number; // 0..1
}

export function Radar({ axes, size = 250 }: { axes: RadarAxis[]; size?: number }) {
  const cx = size / 2;
  const cy = size / 2;
  const R = size / 2 - 38;
  const n = axes.length;

  const pt = (i: number, r: number) => {
    const ang = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return [cx + r * Math.cos(ang), cy + r * Math.sin(ang)];
  };

  const gridLevels = [0.25, 0.5, 0.75, 1];
  const polygon = (r: number) =>
    Array.from({ length: n }, (_, i) => pt(i, r).join(",")).join(" ");

  const dataPts = axes.map((a, i) => pt(i, R * Math.max(0.08, a.score)));
  const dataPoly = dataPts.map((p) => p.join(",")).join(" ");

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* 网格 */}
      {gridLevels.map((g) => (
        <polygon
          key={g}
          points={polygon(R * g)}
          fill="none"
          stroke="rgba(255,255,255,0.07)"
          strokeWidth="1"
        />
      ))}
      {/* 轴线 */}
      {axes.map((_, i) => {
        const [x, y] = pt(i, R);
        return (
          <line
            key={i}
            x1={cx}
            y1={cy}
            x2={x}
            y2={y}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="1"
          />
        );
      })}
      {/* 数据 */}
      <polygon
        points={dataPoly}
        fill="rgba(139,92,246,0.28)"
        stroke="#a855f7"
        strokeWidth="2"
      />
      {dataPts.map((p, i) => (
        <circle key={i} cx={p[0]} cy={p[1]} r="3" fill="#c084fc" />
      ))}
      {/* 标签 */}
      {axes.map((a, i) => {
        const [x, y] = pt(i, R + 20);
        return (
          <text
            key={i}
            x={x}
            y={y}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize="12"
            fill="#a59fc0"
          >
            {a.label}
          </text>
        );
      })}
    </svg>
  );
}

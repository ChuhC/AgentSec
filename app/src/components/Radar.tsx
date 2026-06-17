import React from "react";

export interface RadarAxis {
  label: string;
  score: number; // 0..1
}

export interface RadarSeries {
  name: string;
  color: string;
  fill: string;
  scores: number[]; // 0..1，与 axes 等长
}

export function Radar({
  axes,
  series,
  size = 250,
}: {
  axes: RadarAxis[];
  series?: RadarSeries[];
  size?: number;
}) {
  const cx = size / 2;
  const cy = size / 2;
  const R = size / 2 - 38;
  const n = axes.length;

  const pt = (i: number, r: number) => {
    const ang = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return [cx + r * Math.cos(ang), cy + r * Math.sin(ang)] as const;
  };

  const gridLevels = [0.25, 0.5, 0.75, 1];
  const polygon = (r: number) =>
    Array.from({ length: n }, (_, i) => pt(i, r).join(",")).join(" ");

  const layers: RadarSeries[] =
    series && series.length > 0
      ? series
      : [
          {
            name: "",
            color: "#a855f7",
            fill: "rgba(139,92,246,0.28)",
            scores: axes.map((a) => a.score),
          },
        ];

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {gridLevels.map((g) => (
        <polygon key={g} points={polygon(R * g)} className="radar-grid" />
      ))}
      {axes.map((_, i) => {
        const [x, y] = pt(i, R);
        return <line key={i} x1={cx} y1={cy} x2={x} y2={y} className="radar-axis" />;
      })}
      {layers.map((layer) => {
        const dataPts = layer.scores.map((s, i) => pt(i, R * Math.max(0.08, s)));
        const dataPoly = dataPts.map((p) => p.join(",")).join(" ");
        return (
          <g key={layer.name || "default"}>
            <polygon
              points={dataPoly}
              fill={layer.fill}
              stroke={layer.color}
              strokeWidth="2"
            />
            {dataPts.map((p, i) => (
              <circle key={i} cx={p[0]} cy={p[1]} r="3" fill={layer.color} />
            ))}
          </g>
        );
      })}
      {axes.map((a, i) => {
        const [x, y] = pt(i, R + 20);
        return (
          <text
            key={i}
            x={x}
            y={y}
            textAnchor="middle"
            dominantBaseline="middle"
            className="radar-label"
          >
            {a.label}
          </text>
        );
      })}
    </svg>
  );
}

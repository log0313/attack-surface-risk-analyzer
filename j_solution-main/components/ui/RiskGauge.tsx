"use client";

import React from "react";
import { getCombinedScore } from "@/components/ui/Badge";

interface RiskGaugeProps {
  cvss: number;   // 0–10
  epss: number;   // 0–1
  kev: boolean;   // Known Exploited Vulnerability
  size?: number;
}

/**
 * Semi-circle gauge visualizing combined risk score.
 */
export function RiskGauge({ cvss, epss, kev, size = 160 }: RiskGaugeProps) {
  const combined = getCombinedScore(cvss, epss, kev);  // 0–10 내부 계산값
  const display = Math.round(combined * 10);            // 0–100 표시값
  const combinedPct = combined / 10;                   // 0–1 게이지 비율

  const r = size * 0.38;
  const cx = size / 2;
  const cy = size * 0.58;

  // Semi-circle path (left → right through bottom, 180°)
  const startAngle = -180; // degrees
  const endAngle   = 0;
  const totalArc   = endAngle - startAngle; // 180 deg
  const filledArc  = totalArc * combinedPct;

  function polarToXY(deg: number) {
    const rad = (deg * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  const start  = polarToXY(startAngle);
  const end    = polarToXY(endAngle);
  const filled = polarToXY(startAngle + filledArc);

  const trackPath  = `M ${start.x} ${start.y} A ${r} ${r} 0 0 1 ${end.x} ${end.y}`;
  const filledPath = `M ${start.x} ${start.y} A ${r} ${r} 0 ${filledArc > 180 ? 1 : 0} 1 ${filled.x} ${filled.y}`;

  const color =
    display >= 90 ? "var(--risk-critical)" :
    display >= 70 ? "var(--risk-high)" :
    display >= 40 ? "var(--risk-medium)" : "var(--risk-low)";

  const label =
    display >= 90 ? "Critical" :
    display >= 70 ? "High" :
    display >= 40 ? "Medium" : "Low";

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width={size} height={size * 0.75} viewBox={`0 0 ${size} ${size * 0.65}`} className="-translate-y-3">
        {/* Track */}
        <path d={trackPath} fill="none" stroke="var(--border)" strokeWidth={size * 0.07} strokeLinecap="round" />
        {/* Filled */}
        <path d={filledPath} fill="none" stroke={color} strokeWidth={size * 0.07} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
        {/* Center score */}
        <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize={size * 0.175} fontWeight="700">
          {display}
        </text>
        <text x={cx} y={cy + size * 0.1} textAnchor="middle" fill="var(--text-muted)" fontSize={size * 0.09}>
          / 100
        </text>
      </svg>

      {/* Score breakdown pills */}
      <div className="flex gap-2 flex-wrap justify-center">
        <ScorePill label="CVSS" value={cvss.toFixed(1)} colorClass="text-accent-blue" />
        <ScorePill label="EPSS" value={(epss * 100).toFixed(1) + "%"} colorClass="text-accent-cyan" />
        <ScorePill label="KEV" value={kev ? "Yes" : "No"} colorClass={kev ? "text-risk-critical" : "text-text-muted"} />
      </div>

      <span className="text-[13px] font-bold tracking-[1px] uppercase" style={{ color }}>
        {label} Risk
      </span>
    </div>
  );
}

function ScorePill({ label, value, colorClass }: { label: string; value: string; colorClass: string }) {
  return (
    <div className="bg-bg-surface border border-border rounded-full px-2.5 py-1 flex items-center gap-1.5 text-xs">
      <span className="text-text-muted">{label}</span>
      <span className={`font-bold ${colorClass}`}>{value}</span>
    </div>
  );
}

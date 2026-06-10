"use client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import { RiskDistribution } from "@/lib/types";

const COLORS = {
  Critical: "var(--risk-critical)",
  High:     "var(--risk-high)",
  Medium:   "var(--risk-medium)",
  Low:      "var(--risk-low)",
};

interface CustomLabelProps {
  cx?: number; cy?: number; midAngle?: number;
  innerRadius?: number; outerRadius?: number; percent?: number;
}

function CustomLabel({ cx = 0, cy = 0, midAngle = 0, innerRadius = 0, outerRadius = 0, percent = 0 }: CustomLabelProps) {
  if (percent < 0.06) return null;
  const RADIAN = Math.PI / 180;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central" fontSize={12} fontWeight={600}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
}

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const entry = payload[0];
    return (
      <div className="bg-bg-surface border border-border rounded-lg text-[13px] p-2.5 shadow-md flex items-center gap-2">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.payload.fill }} />
        <span className="text-text-secondary capitalize">{entry.name}:</span>
        <span className="font-bold text-text-primary">{entry.value}</span>
      </div>
    );
  }
  return null;
};

export function RiskPieChart({ distribution }: { distribution?: RiskDistribution }) {
  const DATA = distribution && Object.values(distribution).some((v) => v > 0)
    ? [
        { name: "Critical", value: distribution.critical },
        { name: "High",     value: distribution.high },
        { name: "Medium",   value: distribution.medium },
        { name: "Low",      value: distribution.low },
      ].filter((d) => d.value > 0)
    : [
        { name: "Critical", value: 8 },
        { name: "High",     value: 23 },
        { name: "Medium",   value: 61 },
        { name: "Low",      value: 104 },
      ];

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={DATA}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={95}
          dataKey="value"
          labelLine={false}
          label={CustomLabel}
          strokeWidth={2}
          stroke="var(--bg-card)"
        >
          {DATA.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name as keyof typeof COLORS]} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

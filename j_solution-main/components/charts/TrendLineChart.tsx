"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const MOCK_DATA = [
  { date: "02/24", critical: 5,  high: 18, medium: 52 },
  { date: "03/03", critical: 6,  high: 21, medium: 55 },
  { date: "03/10", critical: 7,  high: 20, medium: 58 },
  { date: "03/17", critical: 6,  high: 22, medium: 60 },
  { date: "03/24", critical: 8,  high: 23, medium: 61 },
];

export type TrendPoint = { date: string; critical: number; high: number; medium: number };

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-bg-surface border border-border rounded-lg text-[13px] p-2.5 shadow-md">
        <p className="m-0 mb-2 font-bold text-text-primary">{label}</p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center gap-2 mt-1 text-text-secondary">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
            <span className="capitalize">{entry.name}:</span>
            <span className="font-bold" style={{ color: entry.color }}>{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export function TrendLineChart({ data }: { data?: TrendPoint[] }) {
  const DATA = data && data.length > 0 ? data : MOCK_DATA;
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={DATA} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
        <XAxis dataKey="date" tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }}
        />
        <Line type="monotone" dataKey="critical" name="Critical" stroke="var(--risk-critical)" strokeWidth={2} dot={{ r: 3, fill: "var(--risk-critical)" }} />
        <Line type="monotone" dataKey="high"     name="High"     stroke="var(--risk-high)"     strokeWidth={2} dot={{ r: 3, fill: "var(--risk-high)" }} />
        <Line type="monotone" dataKey="medium"   name="Medium"   stroke="var(--risk-medium)"   strokeWidth={2} dot={{ r: 3, fill: "var(--risk-medium)" }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

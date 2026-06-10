import React from "react";

interface BadgeProps {
  level: "critical" | "high" | "medium" | "low" | "info";
  children?: React.ReactNode;
}

const LABELS: Record<BadgeProps["level"], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function Badge({ level, children }: BadgeProps) {
  return (
    <span className={`badge badge-${level}`}>
      {children ?? LABELS[level]}
    </span>
  );
}

export function levelFromScore(score: number): BadgeProps["level"] {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0)    return "low";
  return "info";
}

export function getCombinedScore(cvss: number, epss: number, kev: boolean): number {
  return Math.min(10, cvss * 0.5 + epss * 10 * 0.3 + (kev ? 10 : 0) * 0.2);
}

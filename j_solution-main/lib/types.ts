export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

export interface Asset {
  id: string;
  subdomain: string;
  ip: string;
  port: number;
  service: string;
  version?: string;
  cvss: number;
  status: "open" | "filtered" | "closed";
  scannedAt?: string;
}

export interface CveEntry {
  id: string;
  cvss: number;
  epss: number;
  kev: boolean;
  summary: string;
  publishedDate?: string;
}

export interface PortInfo {
  port: number;
  protocol: string;
  service: string;
  version: string;
  state: string;
}

export interface Risk {
  id: string;
  asset: string;
  ip: string;
  cvss: number;
  epss: number;
  kev: boolean;
  cve: string;
  service: string;
  description?: string;
  ports?: PortInfo[];
  cveList?: CveEntry[];
  scannedAt?: string;
}

export type ScanStatus = "queued" | "running" | "done" | "error";

export interface ScanJob {
  jobId: string;
  target: string;
  status: ScanStatus;
  phase?: string;
  createdAt: string;
  finishedAt?: string;
  error?: string;
}

export interface DashboardMetrics {
  totalAssets: number;
  activePorts: number;
  riskScore: number;
  criticalCount: number;
  assetDelta: number;
}

export interface RiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

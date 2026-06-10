"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { Badge, levelFromScore } from "@/components/ui/Badge";
import { Card, CardHeader } from "@/components/ui/Card";
import { Pagination } from "@/components/ui/Pagination";
import { Asset, ScanJob } from "@/lib/types";

type FilterLevel = "all" | "critical" | "high" | "medium" | "low";
const ITEMS_PER_PAGE = 6;

const SCAN_PHASES: Record<string, string> = {
  queued:  "대기 중...",
  running: "스캔 진행 중...",
  done:    "완료",
  error:   "오류 발생",
};

const PHASE_STEPS = [
  { key: "naabu",  label: "Naabu (포트 스캔)" },
  { key: "nmap",   label: "Nmap (서비스 탐지)" },
  { key: "httpx",  label: "HTTPX (HTTP 프로브)" },
];

export default function AssetsPage() {
  const [domain, setDomain]         = useState("");
  const [job, setJob]               = useState<ScanJob | null>(null);
  const [assets, setAssets]         = useState<Asset[]>([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [filter, setFilter]         = useState<FilterLevel>("all");
  const [search, setSearch]         = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [dataSource, setDataSource] = useState<"opensearch" | "mock">("mock");

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({
      size: "100",
      ...(search ? { search } : {}),
    });
    const res = await fetch(`/api/assets?${params}`);
    const data = await res.json();
    setAssets(data.assets ?? []);
    setTotal(data.total ?? 0);
    setDataSource(data.source ?? "mock");
    setLoading(false);
  }, [search]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const pollJob = useCallback(async (jobId: string) => {
    const interval = setInterval(async () => {
      const res = await fetch(`/api/scan/status/${jobId}`);
      if (!res.ok) { clearInterval(interval); return; }
      const data: ScanJob = await res.json();
      setJob(data);
      if (data.status === "done" || data.status === "error") {
        clearInterval(interval);
        if (data.status === "done") fetchAssets();
      }
    }, 2000);
  }, [fetchAssets]);

  const handleScan = async () => {
    if (!domain.trim()) return;
    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: domain.trim() }),
    });
    if (!res.ok) {
      alert("Redis에 연결할 수 없습니다. 백엔드를 확인하세요.");
      return;
    }
    const data = await res.json();
    const newJob: ScanJob = { jobId: data.jobId, target: domain.trim(), status: "queued", createdAt: new Date().toISOString() };
    setJob(newJob);
    pollJob(data.jobId);
  };

  const handleStop = () => setJob(null);

  const handleReset = async () => {
    if (!confirm("스캔된 모든 자산 데이터를 초기화하시겠습니까?")) return;
    await fetch("/api/assets", { method: "DELETE" });
    setJob(null);
    fetchAssets();
  };

  const filtered = assets.filter((a) => {
    const level = levelFromScore(a.cvss);
    return filter === "all" || level === filter;
  });

  const totalPages = Math.ceil(filtered.length / ITEMS_PER_PAGE);
  const paginated  = filtered.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  const isScanning = job && (job.status === "queued" || job.status === "running");

  return (
    <>
      <div>
        <h1 className="m-0 text-[22px] font-bold text-text-primary">Asset Discovery</h1>
        <p className="mt-1 mb-0 text-[13px] text-text-muted">도메인 스캔 파이프라인 제어 및 수집된 외부 자산 관리</p>
      </div>

      {/* Scan Input */}
      <Card>
        <CardHeader title="스캔 파이프라인 제어" subtitle="Subfinder → Naabu → Nmap → HTTPX 순서로 실행됩니다" />
        <div className="flex gap-2.5">
          <input
            type="text"
            placeholder="example.com 또는 192.168.1.0/24"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !isScanning && handleScan()}
            disabled={!!isScanning}
            className="flex-1 disabled:opacity-50"
          />
          <button
            className={`${isScanning ? "btn-danger" : "btn-primary"} whitespace-nowrap min-w-[110px]`}
            onClick={isScanning ? handleStop : handleScan}
          >
            {isScanning ? "⬛ 중지" : "▶ 스캔 시작"}
          </button>
          <button
            className="btn-danger whitespace-nowrap"
            onClick={handleReset}
            disabled={!!isScanning}
            title="수집된 모든 자산 데이터 초기화"
          >
            🗑 초기화
          </button>
        </div>

        {job && (
          <div className={`mt-3.5 px-3.5 py-3 bg-bg-surface rounded-lg border ${job.status === "error" ? "border-risk-critical" : "border-border"}`}>
            <div className="flex items-center gap-2.5 mb-2">
              {isScanning && <span className="w-2 h-2 rounded-full bg-risk-high inline-block animate-[pulse-glow_1s_infinite]" />}
              <span className={`text-[13px] font-semibold ${job.status === "error" ? "text-risk-critical" : job.status === "done" ? "text-risk-low" : "text-risk-high"}`}>
                {SCAN_PHASES[job.status]} — {job.target}
              </span>
              {job.status === "done" && <span className="text-[11px] text-text-muted">자산 목록이 업데이트되었습니다</span>}
            </div>
            {isScanning && (
              <div className="flex gap-6 text-xs text-text-muted">
                {PHASE_STEPS.map((s) => (
                  <span key={s.key} className={job.phase === s.key ? "text-accent-blue" : ""}>
                    {job.phase === s.key ? "⟳" : "◻"} {s.label}
                  </span>
                ))}
              </div>
            )}
            {job.status === "error" && (
              <p className="m-0 text-xs text-risk-critical">{job.error ?? "알 수 없는 오류가 발생했습니다."}</p>
            )}
          </div>
        )}
      </Card>

      {/* Asset List */}
      <Card>
        <CardHeader
          title={`자산 목록 (${filtered.length}개${dataSource === "mock" ? " — 샘플 데이터" : ""})`}
          subtitle="수집된 외부 서브도메인 및 서비스"
          action={
            <div className="flex gap-2 items-center">
              <input
                type="search"
                placeholder="검색..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setCurrentPage(1); }}
                className="w-40 px-2.5 py-1.5 text-xs"
              />
              {(["all","critical","high","medium","low"] as FilterLevel[]).map((f) => (
                <button
                  key={f}
                  className={`btn-ghost px-2.5 py-1 text-[11px] ${filter === f ? "border-accent-blue text-accent-blue" : "border-border text-text-muted"}`}
                  onClick={() => { setFilter(f); setCurrentPage(1); }}
                >
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          }
        />
        <div className="overflow-x-auto min-h-[345px]">
          {loading ? (
            <div className="flex flex-col gap-2.5 pt-2">
              {[...Array(6)].map((_, i) => <div key={i} className="skeleton h-10 rounded" />)}
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  {["Subdomain","IP Address","Port","Service","Status","CVSS","Risk",""].map((h) => (
                    <th key={h} className="font-semibold text-[11px] uppercase tracking-[0.8px] text-text-muted pb-2 border-b border-border">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paginated.map((a) => (
                  <tr key={a.id} className="border-b border-border-subtle hover:bg-bg-hover transition-colors">
                    <td className="py-3 pr-4 text-text-primary font-medium">{a.subdomain}</td>
                    <td className="py-3 pr-4 font-mono text-xs">{a.ip}</td>
                    <td className="py-3 pr-4 font-mono text-xs">{a.port}</td>
                    <td className="py-3 pr-4">{a.service}</td>
                    <td className="py-3 pr-4">
                      <span className={`text-[11px] font-semibold ${a.status === "open" ? "text-risk-low" : "text-text-muted"}`}>
                        ● {a.status}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-text-primary font-semibold">{a.cvss > 0 ? a.cvss.toFixed(1) : "—"}</td>
                    <td className="py-3 pr-4"><Badge level={levelFromScore(a.cvss)} /></td>
                    <td className="py-3 pl-4 text-right">
                      {a.cvss > 0 ? (
                        <Link href={`/risk/${a.id}`} className="text-[11px] text-text-primary no-underline px-2 py-1 border border-[rgba(0,199,169,0.35)] rounded hover:bg-[rgba(0,199,169,0.1)] transition-colors inline-block whitespace-nowrap">
                          분석 →
                        </Link>
                      ) : (
                        <span className="text-[10px] text-text-muted px-2 py-1 uppercase tracking-[0.8px]">안전함</span>
                      )}
                    </td>
                  </tr>
                ))}
                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-text-muted text-sm">해당 조건의 자산이 없습니다.</td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
        {totalPages > 1 && (
          <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={setCurrentPage} />
        )}
      </Card>
    </>
  );
}

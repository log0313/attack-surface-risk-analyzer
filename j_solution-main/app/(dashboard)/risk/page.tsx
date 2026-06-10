"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Badge, levelFromScore, getCombinedScore } from "@/components/ui/Badge";
import { Card, CardHeader } from "@/components/ui/Card";
import { Pagination } from "@/components/ui/Pagination";
import { Risk, RiskLevel } from "@/lib/types";

const ITEMS_PER_PAGE = 5;

export default function RiskListPage() {
  const [risks, setRisks]             = useState<Risk[]>([]);
  const [loading, setLoading]         = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [dataSource, setDataSource]   = useState<"opensearch" | "mock">("mock");
  const [search, setSearch]           = useState("");
  const [assetFilter, setAssetFilter] = useState("all");

  useEffect(() => {
    fetch("/api/risks?size=500")
      .then((r) => r.json())
      .then((data) => {
        setRisks(data.risks ?? []);
        setDataSource(data.source ?? "mock");
      })
      .finally(() => setLoading(false));
  }, []);

  // 자산 목록 (드롭다운용)
  const assetOptions = ["all", ...Array.from(new Set(risks.map((r) => r.asset).filter(Boolean)))];

  const filtered = [...risks]
    .filter((r) => {
      const q = search.toLowerCase();
      const matchSearch = !q ||
        r.asset.toLowerCase().includes(q) ||
        r.ip.toLowerCase().includes(q) ||
        r.cve.toLowerCase().includes(q) ||
        r.service.toLowerCase().includes(q);
      const matchAsset = assetFilter === "all" || r.asset === assetFilter;
      return matchSearch && matchAsset;
    })
    .sort((a, b) => getCombinedScore(b.cvss, b.epss, b.kev) - getCombinedScore(a.cvss, a.epss, a.kev));

  const totalPages = Math.ceil(filtered.length / ITEMS_PER_PAGE);
  const paginated  = filtered.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  // 요약 카운트는 필터 적용 결과 기준
  const summary: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  filtered.forEach((r) => { summary[levelFromScore(getCombinedScore(r.cvss, r.epss, r.kev))]++; });

  const handleFilterChange = (value: string) => {
    setAssetFilter(value);
    setCurrentPage(1);
  };

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setCurrentPage(1);
  };

  return (
    <>
      <div>
        <h1 className="m-0 text-[22px] font-bold text-text-primary">Risk Analysis</h1>
        <p className="mt-1 mb-0 text-[13px] text-text-muted">
          식별된 취약점 및 위험 자산 전체 목록{dataSource === "mock" ? " — 샘플 데이터" : ""}
          {assetFilter !== "all" && <span className="ml-2 text-accent-blue font-semibold">· {assetFilter}</span>}
        </p>
      </div>

      {/* Summary bar */}
      <div className="flex gap-2.5">
        {(["critical","high","medium","low"] as const).map((level) => (
          <div key={level} className="flex-1 py-3 px-4 bg-bg-card border border-border rounded-xl flex items-center justify-between">
            <span className="text-xs text-text-muted capitalize">{level}</span>
            {loading ? (
              <div className="skeleton h-7 w-8 rounded" />
            ) : (
              <span className={`text-[22px] font-extrabold ${
                level === "critical" ? "text-risk-critical" :
                level === "high"     ? "text-risk-high" :
                level === "medium"   ? "text-risk-medium" : "text-risk-low"
              }`}>{summary[level]}</span>
            )}
          </div>
        ))}
      </div>

      <Card>
        <CardHeader
          title="취약점 목록"
          subtitle="CVSS × EPSS × KEV 종합 위험 점수 기준 정렬"
          action={
            <div className="flex gap-2 items-center">
              <input
                type="search"
                placeholder="자산 · CVE · 서비스 검색..."
                value={search}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="w-48 px-2.5 py-1.5 text-xs"
              />
              <select
                value={assetFilter}
                onChange={(e) => handleFilterChange(e.target.value)}
                className="px-2.5 py-1.5 text-xs bg-bg-surface border border-border rounded text-text-primary"
              >
                {assetOptions.map((a) => (
                  <option key={a} value={a}>{a === "all" ? "전체 자산" : a}</option>
                ))}
              </select>
            </div>
          }
        />
        <div className="overflow-x-auto min-h-[300px]">
          {loading ? (
            <div className="flex flex-col gap-2.5 pt-2">
              {[...Array(5)].map((_, i) => <div key={i} className="skeleton h-12 rounded" />)}
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  {["Asset","IP","Service","CVE","CVSS","EPSS","KEV","Risk",""].map((h) => (
                    <th key={h} className="font-semibold text-[11px] uppercase tracking-[0.8px] text-text-muted pb-2 border-b border-border">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paginated.map((r) => {
                  const finalScore = getCombinedScore(r.cvss, r.epss, r.kev);
                  return (
                    <tr key={r.id} className="border-b border-border-subtle hover:bg-bg-hover transition-colors">
                      <td className="py-3 pr-4 text-text-primary font-medium">{r.asset || <span className="text-text-muted">—</span>}</td>
                      <td className="py-3 pr-4 font-mono text-xs">{r.ip || <span className="text-text-muted">—</span>}</td>
                      <td className="py-3 pr-4 text-xs">{r.service || <span className="text-text-muted">—</span>}</td>
                      <td className="py-3 pr-4 font-mono text-xs text-text-secondary">{r.cve}</td>
                      <td className="py-3 pr-4 font-bold text-text-primary">{r.cvss.toFixed(1)}</td>
                      <td className="py-3 pr-4">{(r.epss * 100).toFixed(0)}%</td>
                      <td className="py-3 pr-4">{r.kev ? <span className="text-risk-critical font-bold">● Yes</span> : <span className="text-text-muted">No</span>}</td>
                      <td className="py-3 pr-4"><Badge level={levelFromScore(finalScore)} /></td>
                      <td className="py-3 pl-4 text-right">
                        <Link href={`/risk/${r.id}`} className="text-[11px] text-text-primary no-underline px-2 py-1 border border-[rgba(0,199,169,0.35)] rounded hover:bg-[rgba(0,199,169,0.1)] transition-colors inline-block whitespace-nowrap">
                          상세 →
                        </Link>
                      </td>
                    </tr>
                  );
                })}
                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={9} className="py-8 text-center text-text-muted text-sm">취약점 데이터가 없습니다.</td>
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

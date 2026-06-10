"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Card, CardHeader } from "@/components/ui/Card";
import { Risk } from "@/lib/types";

function ReportsContent() {
  const searchParams = useSearchParams();
  const preselectedId = searchParams.get("id");

  const [risks, setRisks]           = useState<Risk[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [loading, setLoading]       = useState(false);
  const [fetchingRisks, setFetchingRisks] = useState(true);
  const [report, setReport]         = useState<string | null>(null);
  const [reportSource, setReportSource] = useState<"gemini" | "fallback" | null>(null);

  useEffect(() => {
    const loadRisks = async () => {
      try {
        // 기본 목록 로드
        const res  = await fetch("/api/risks?size=100");
        const data = await res.json();
        // (asset, cve) 기준 중복 제거 — cvss 높은 것 우선
        const raw: Risk[] = (data.risks ?? []).filter((r: Risk) => r.cvss > 0);
        const seen = new Map<string, Risk>();
        raw.forEach((r) => {
          const key = `${r.asset}__${r.cve}`;
          if (!seen.has(key) || r.cvss > seen.get(key)!.cvss) seen.set(key, r);
        });
        let list: Risk[] = Array.from(seen.values());

        // preselectedId가 있으면 해당 risk를 직접 조회해서 보장
        if (preselectedId) {
          const inList = list.find((r) => r.id === preselectedId);
          if (!inList) {
            try {
              const detailRes  = await fetch(`/api/risks/${preselectedId}`);
              const detailData = await detailRes.json();
              if (detailData.risk) list = [detailData.risk, ...list];
            } catch { /* 조회 실패 시 무시 */ }
          }
          setRisks(list);
          const target = list.find((r) => r.id === preselectedId);
          if (target) {
            setSelectedId(target.id);
            generateReport(target);
            return;
          }
        }

        setRisks(list);
        setSelectedId(list[0]?.id ?? "");
      } finally {
        setFetchingRisks(false);
      }
    };

    loadRisks();
  }, [preselectedId]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedRisk = risks.find((r) => r.id === selectedId);

  const generateReport = async (risk: Risk) => {
    setLoading(true);
    setReport(null);
    setReportSource(null);

    const res = await fetch("/api/reports/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ risk }),
    });
    const data = await res.json();
    setReport(data.report ?? "보고서 생성에 실패했습니다.");
    setReportSource(data.source === "gemini" ? "gemini" : "fallback");
    setLoading(false);
  };

  const handleGenerate = () => {
    if (!selectedRisk) return;
    generateReport(selectedRisk);
  };

  const remediationLines = report
    ? report
        .split("\n")
        .filter((l) => /^\d+\./.test(l.trim()))
        .map((l) => l.replace(/^\d+\.\s*/, "").trim())
        .filter(Boolean)
    : [];

  return (
    <>
      <div>
        <h1 className="m-0 text-[22px] font-bold text-text-primary">AI Reports</h1>
        <p className="mt-1 mb-0 text-[13px] text-text-muted">Gemini 기반 보안 보고서 자동 생성 및 대응 가이드</p>
      </div>

      {/* Control Panel */}
      <Card>
        <CardHeader title="보고서 생성 설정" />
        <div className="flex gap-3 items-end">
          <div className="flex-1">
            <label className="block text-[11px] text-text-muted mb-1.5 uppercase tracking-[0.8px]">
              분석 대상 취약점 선택
            </label>
            {fetchingRisks ? (
              <div className="skeleton h-10 rounded-lg" />
            ) : (
              <select
                value={selectedId}
                onChange={(e) => { setSelectedId(e.target.value); setReport(null); }}
                className="w-full px-3.5 py-2.5 bg-bg-surface border border-border rounded-lg text-text-primary text-sm outline-none focus:border-accent-blue focus:shadow-[0_0_0_3px_rgba(88,166,255,0.1)] transition-all"
              >
                {risks.map((r) => (
                  <option key={r.id} value={r.id} className="bg-bg-surface">
                    {r.asset} — {r.cve} (CVSS {r.cvss.toFixed(1)}{r.kev ? " ⚠ KEV" : ""})
                  </option>
                ))}
              </select>
            )}
          </div>
          <button
            className={`btn-primary flex items-center justify-center gap-2 min-w-[160px] ${loading ? "opacity-70 cursor-not-allowed" : ""}`}
            onClick={handleGenerate}
            disabled={loading || !selectedRisk}
          >
            {loading ? (
              <>
                <span className="inline-block w-3.5 h-3.5 border-2 border-[rgba(0,0,0,0.3)] border-t-[#0d1117] rounded-full animate-spin-slow" />
                생성 중...
              </>
            ) : (
              "✦ 보고서 생성"
            )}
          </button>
        </div>

        {/* Selected risk summary */}
        {selectedRisk && (
          <div className="mt-3 flex gap-4 text-xs text-text-muted pt-3 border-t border-border">
            <span>IP: <span className="font-mono text-text-secondary">{selectedRisk.ip}</span></span>
            <span>서비스: <span className="text-text-secondary">{selectedRisk.service}</span></span>
            <span>EPSS: <span className="text-text-secondary">{(selectedRisk.epss * 100).toFixed(0)}%</span></span>
            {selectedRisk.kev && <span className="text-risk-critical font-semibold">⚠ KEV 등재 — 실제 공격 진행 중</span>}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4">
        {/* Report Editor */}
        <Card>
          <CardHeader
            title="생성된 보고서 초안"
            subtitle={reportSource === "gemini" ? "Gemini 1.5 Pro 생성" : report ? "자동 생성 (Gemini 키 미설정)" : "보고서를 생성하면 여기에 표시됩니다"}
            action={report ? (
              <button className="btn-ghost text-[11px] px-2.5 py-1.5" onClick={() => navigator.clipboard.writeText(report)}>
                복사
              </button>
            ) : undefined}
          />
          {loading && (
            <div className="flex flex-col gap-2.5">
              {[80, 60, 90, 50, 70].map((w, i) => (
                <div key={i} className="skeleton h-4" style={{ width: `${w}%` }} />
              ))}
            </div>
          )}
          {!loading && !report && (
            <div className="min-h-[300px] flex flex-col items-center justify-center gap-3 text-text-muted text-[13px]">
              <span className="text-4xl text-accent-purple">✦</span>
              <p className="m-0">취약점을 선택하고 보고서 생성을 클릭하세요</p>
            </div>
          )}
          {report && !loading && (
            <textarea
              value={report}
              onChange={(e) => setReport(e.target.value)}
              className="min-h-[380px] w-full resize-y font-mono text-[13px] leading-[1.8] p-4 bg-bg-surface border border-border rounded-lg text-text-primary focus:border-accent-blue focus:shadow-[0_0_0_3px_rgba(88,166,255,0.1)] transition-all"
            />
          )}
        </Card>

        {/* Remediation Guide */}
        <Card>
          <CardHeader title="대응 가이드" subtitle="Remediation Guide" />
          {remediationLines.length === 0 ? (
            <p className="text-[13px] text-text-muted">보고서를 생성하면 대응 가이드가 표시됩니다.</p>
          ) : (
            <div className="flex flex-col gap-3">
              {remediationLines.map((item, i) => (
                <div key={i} className="bg-bg-surface rounded-lg border border-border border-l-3 border-l-accent-blue py-3 px-3.5 flex gap-2.5">
                  <span className="min-w-[22px] h-[22px] rounded-full bg-[rgba(88,166,255,0.15)] text-accent-blue flex items-center justify-center text-[11px] font-bold">
                    {i + 1}
                  </span>
                  <p className="m-0 text-xs leading-[1.7] text-text-secondary">{item}</p>
                </div>
              ))}
            </div>
          )}

          {/* Gemini badge */}
          <div className="mt-4 py-2.5 px-3.5 bg-[rgba(0,199,169,0.08)] border border-[rgba(0,199,169,0.25)] rounded-lg flex items-center gap-2">
            <span className="text-base text-accent-purple">✦</span>
            <div>
              <div className="text-[11px] font-bold text-accent-purple">Powered by Gemini</div>
              <div className="text-[10px] text-text-muted">AI 가이드는 참고용입니다. 전문가 검토 후 적용하세요.</div>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}

export default function ReportsPage() {
  return (
    <Suspense fallback={<div className="text-text-muted text-sm">로딩 중...</div>}>
      <ReportsContent />
    </Suspense>
  );
}

import { notFound } from "next/navigation";
import Link from "next/link";
import { RiskGauge } from "@/components/ui/RiskGauge";
import { Badge, levelFromScore, getCombinedScore } from "@/components/ui/Badge";
import { Card, CardHeader } from "@/components/ui/Card";
import { Risk } from "@/lib/types";

async function getRisk(id: string): Promise<Risk | null> {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL ?? "http://localhost:3000";
  try {
    const res = await fetch(`${baseUrl}/api/risks/${id}`, { cache: "no-store" });
    if (!res.ok) return null;
    const data = await res.json();
    return data.risk ?? null;
  } catch {
    return null;
  }
}

export default async function RiskDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await getRisk(id);
  if (!data) notFound();

  const finalScore = getCombinedScore(data.cvss, data.epss, data.kev);

  return (
    <>
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs text-text-muted">
        <Link href="/risk" className="text-accent-blue no-underline hover:text-accent-cyan">Risk Analysis</Link>
        <span>/</span>
        <span className="text-text-secondary">{data.asset}</span>
      </div>

      <div className="flex items-start justify-between">
        <div>
          <h1 className="m-0 text-[22px] font-bold text-text-primary">{data.asset}</h1>
          <div className="flex gap-2 mt-1.5 items-center">
            <Badge level={levelFromScore(finalScore)} />
            <span className="text-xs font-mono text-accent-blue">{data.cve}</span>
            <span className="text-xs text-text-muted">{data.service}</span>
          </div>
        </div>
        <Link
          href={`/reports?id=${id}`}
          className="px-4 py-2 bg-[rgba(88,166,255,0.1)] border border-[rgba(88,166,255,0.3)] rounded-lg text-accent-blue text-[13px] font-semibold no-underline hover:bg-[rgba(88,166,255,0.15)] transition-colors"
        >
          ✦ AI 보고서 생성
        </Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4">
        {/* Risk Scorecard */}
        <Card className="flex flex-col items-center justify-center">
          <p className="m-0 mb-4 text-xs font-semibold text-text-muted uppercase tracking-[0.8px]">
            종합 리스크 스코어카드
          </p>
          <RiskGauge cvss={data.cvss} epss={data.epss} kev={data.kev} size={180} />
        </Card>

        {/* Vulnerability Description */}
        <Card>
          <CardHeader title="취약점 개요" />
          <p className="m-0 text-sm leading-[1.8] text-text-secondary">
            {data.description ?? `${data.service}에서 발견된 취약점(${data.cve})입니다. 상세 분석을 위해 AI 보고서를 생성하세요.`}
          </p>

          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-2.5">
            {[
              { label: "IP Address", value: data.ip },
              { label: "Service",    value: data.service },
              { label: "KEV Status", value: data.kev ? "⚠ 실제 악용 중" : "미등재", danger: data.kev },
            ].map(({ label, value, danger }) => (
              <div
                key={label}
                className={`bg-bg-surface rounded-lg border p-2.5 ${danger ? "border-[rgba(255,77,79,0.25)]" : "border-border"}`}
              >
                <div className="text-[10px] text-text-muted uppercase tracking-[0.8px] mb-1">{label}</div>
                <div className={`text-[13px] font-semibold ${danger ? "text-risk-critical" : "text-text-primary"} ${label === "IP Address" ? "font-mono" : ""}`}>
                  {value}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Port & Service Info */}
      {data.ports && data.ports.length > 0 && (
        <Card>
          <CardHeader title="포트 및 서비스 정보" subtitle="Nmap 스캔 결과" />
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  {["Port","Protocol","Service","Version","State"].map((h) => (
                    <th key={h} className="font-semibold text-[11px] uppercase tracking-[0.8px] text-text-muted pb-2 border-b border-border px-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.ports.map((p) => (
                  <tr key={p.port} className="border-b border-border-subtle hover:bg-bg-hover transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-accent-cyan">{p.port}</td>
                    <td className="py-3 px-4 text-text-secondary">{p.protocol}</td>
                    <td className="py-3 px-4 text-text-primary">{p.service}</td>
                    <td className="py-3 px-4 font-mono text-xs text-text-secondary">{p.version}</td>
                    <td className="py-3 px-4"><span className="text-risk-low text-xs font-semibold">● {p.state}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* CVE List */}
      {data.cveList && data.cveList.length > 0 && (
        <Card>
          <CardHeader title="관련 CVE 목록" />
          <div className="flex flex-col gap-2.5">
            {data.cveList.map((c) => (
              <div
                key={c.id}
                className="bg-bg-surface rounded-lg border border-border p-3 flex flex-wrap md:flex-nowrap items-center gap-3.5"
              >
                <span className="font-mono text-[13px] text-accent-blue min-w-[140px]">{c.id}</span>
                <Badge level={levelFromScore(c.cvss)} />
                <span className="text-[13px] text-text-secondary flex-1">{c.summary}</span>
                <div className="flex items-center gap-2">
                  {c.kev && <span className="text-[10px] text-risk-critical font-bold px-1.5 py-0.5 border border-[rgba(255,77,79,0.4)] rounded">KEV</span>}
                  <span className={`text-xl font-extrabold ${c.cvss >= 9 ? "text-risk-critical" : "text-risk-high"}`}>
                    {c.cvss.toFixed(1)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}

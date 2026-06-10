import { NextRequest, NextResponse } from "next/server";
import { Risk } from "@/lib/types";

interface GenerateRequest {
  risk: Risk;
}

const LLM_API_URL = process.env.LLM_REPORT_URL ?? "http://localhost:8000";

// ── LLM Report Module (FastAPI) 호출 ─────────────────────────────
async function callLLMModule(risk: Risk): Promise<string> {
  const res = await fetch(`${LLM_API_URL}/api/llm/report/vulnerability`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      domain:      risk.asset,
      ip:          risk.ip,
      service_name: risk.service,
      cve_id:      risk.cve || "UNKNOWN",
      cvss_score:  risk.cvss,
      epss_score:  risk.epss,
      kev_status:  risk.kev,
      language:    "ko",
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) throw new Error(`LLM Module error: ${res.status}`);

  const data = await res.json();

  // FastAPI 응답 → 마크다운 리포트로 변환
  const reportText: string = data.report_text ?? "";
  const summary: string    = data.risk_summary ?? "";
  const reasons: string[]  = data.risk_reasons ?? [];
  const actions: string[]  = data.recommended_actions ?? [];
  const priority: string   = data.priority ?? "";

  // report_text가 있으면 그대로, 없으면 구조화된 내용으로 조합
  if (reportText && reportText.length > 100) return reportText;

  const date = new Date().toISOString().split("T")[0];
  return `# 보안 취약점 분석 보고서
**생성일**: ${date} | **대상**: ${risk.asset} | **우선순위**: ${priority}

## 요약 (Executive Summary)
${summary}

## 위험 원인
${reasons.map((r) => `- ${r}`).join("\n")}

## 대응 권고사항
${actions.map((a, i) => `${i + 1}. ${a}`).join("\n")}`;
}

// ── Gemini 직접 호출 (폴백) ───────────────────────────────────────
function buildPrompt(risk: Risk): string {
  const kevLabel = risk.kev ? "Yes — 현재 실제 악용 중 (CISA KEV 등재)" : "No";
  return `당신은 사이버보안 전문가입니다. 아래 취약점 정보를 바탕으로 한국어로 보안 보고서를 작성하세요.

## 취약점 정보
- 대상 자산: ${risk.asset} (${risk.ip})
- 서비스: ${risk.service}
- CVE: ${risk.cve}
- CVSS 점수: ${risk.cvss}
- EPSS 점수: ${(risk.epss * 100).toFixed(1)}%
- KEV 등재 여부: ${kevLabel}
${risk.description ? `- 설명: ${risk.description}` : ""}

## 작성 지침
다음 구조로 마크다운 형식의 보고서를 작성하세요:

# 보안 취약점 분석 보고서

**생성일**: ${new Date().toISOString().split("T")[0]} | **대상**: ${risk.asset} | **위험도**: (Critical/High/Medium/Low 중 선택)

## 요약 (Executive Summary)
(2-3문장으로 핵심 위협 요약)

## 기술적 분석
(취약점 유형, 공격 경로, 영향 범위)

## 위험 평가
(CVSS, EPSS, KEV 지표 해석 및 조직 영향도)

## 대응 권고사항
1. (즉각 조치)
2. (단기 대응)
3. (장기 보완)

보고서는 실용적이고 구체적으로 작성하세요.`;
}

async function callGeminiDirect(risk: Risk): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("no key");

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: buildPrompt(risk) }] }],
        generationConfig: { temperature: 0.4, maxOutputTokens: 1500 },
      }),
    }
  );
  if (!res.ok) throw new Error(`Gemini error: ${res.status}`);
  const data = await res.json();
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error("empty response");
  return text;
}

// ── 하드코딩 폴백 ─────────────────────────────────────────────────
function buildFallbackReport(risk: Risk): string {
  const date  = new Date().toISOString().split("T")[0];
  const level = risk.cvss >= 9 ? "Critical" : risk.cvss >= 7 ? "High" : risk.cvss >= 4 ? "Medium" : "Low";
  return `# 보안 취약점 분석 보고서
**생성일**: ${date} | **대상**: ${risk.asset} | **위험도**: ${level}

## 요약 (Executive Summary)

${risk.asset} (${risk.ip})에서 운영 중인 ${risk.service} 서비스에서 **${risk.cve}** (CVSS ${risk.cvss}) 취약점이 발견되었습니다.${risk.kev ? " 해당 취약점은 CISA KEV에 등재되어 **현재 실제 공격이 진행 중**입니다." : ""} EPSS 점수 ${(risk.epss * 100).toFixed(0)}%로 악용 가능성이 ${risk.epss > 0.5 ? "매우 높습니다" : "존재합니다"}.

## 기술적 분석

${risk.description ?? `${risk.service}에서 발견된 ${level} 등급의 취약점으로, 즉각적인 조치가 필요합니다.`}

## 위험 평가

- **CVSS ${risk.cvss}**: ${level} 위험 등급
- **EPSS ${(risk.epss * 100).toFixed(0)}%**: 실제 악용 확률
- **KEV**: ${risk.kev ? "⚠ 실제 공격에 악용 중 — 즉각 패치 필요" : "미등재"}

## 대응 권고사항

1. 해당 서비스의 최신 보안 패치를 즉시 적용하세요.
2. 외부 노출된 포트에 대한 방화벽 접근 제어를 검토하세요.
3. 접근 로그를 점검하고 이상 징후를 확인하세요.`;
}

// ── 메인 핸들러 ───────────────────────────────────────────────────
export async function POST(req: NextRequest) {
  const { risk }: GenerateRequest = await req.json();
  if (!risk) {
    return NextResponse.json({ error: "risk is required" }, { status: 400 });
  }

  // 1순위: LLM Report Module (FastAPI)
  try {
    const report = await callLLMModule(risk);
    return NextResponse.json({ report, source: "llm-module" });
  } catch { /* FastAPI 미실행 또는 오류 → 다음 단계 */ }

  // 2순위: Gemini 직접 호출
  try {
    const report = await callGeminiDirect(risk);
    return NextResponse.json({ report, source: "gemini" });
  } catch { /* API 키 없음 또는 오류 → 폴백 */ }

  // 3순위: 하드코딩 폴백
  return NextResponse.json({ report: buildFallbackReport(risk), source: "fallback" });
}

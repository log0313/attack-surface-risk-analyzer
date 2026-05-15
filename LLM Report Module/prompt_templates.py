"""LLM Prompt Template.

기본 출력 언어: 한국어 (ko)
지원 언어: ko / en / zh — REPORT_LANGUAGE 환경변수 또는 호출 시 인자로 변경.
"""
import json


# ───────────────────────────────────────────────
# System Prompt (역할/규칙 정의)
# ───────────────────────────────────────────────

_SYSTEM_KO = """당신은 금융권 보안 분석가를 보조하는 AI 보안 어시스턴트입니다.
이미 산출된 취약점 분석 결과(Logistic Regression 기반 threat_score)를 바탕으로,
자연어 해설과 조치 가이드 초안을 작성하는 역할만 수행합니다.

[엄수 사항]
1. 응답은 반드시 지정된 JSON 스키마를 따라야 하며, 그 외 어떤 텍스트도 포함하지 마십시오.
2. 입력에 명시되지 않은 사실(존재하지 않는 패치 URL, 미확인 익스플로잇 코드 등)을 만들어내지 마십시오.
3. 패치/조치 정보가 입력에 없으면 "공식 보안 권고문 및 최신 버전을 확인하여 적용을 검토하십시오"로만 답하십시오.
4. 본 결과는 '조치 가이드 초안(draft)'이며, 최종 보안 명령이 아닙니다. 최종 보안 조치는 담당자 검토가 필요함을 명시하십시오.
5. **위험 점수는 절대 재계산하지 마십시오.**
   입력으로 받은 final_risk_score / risk_level / priority / weight_detail 만 인용하십시오.
6. 위험 점수 해석 규칙:
   - 위험 점수는 Logistic Regression 기반 threat_score (0~100) 이며, KEV 등재 시 100점으로 override 됩니다.
   - 분급: 100 → Immediate, ≥84.4 → High(고위험군), ≥24.3 → Medium(잠재 위협), <24.3 → Low(수용 가능 위협).
   - 다음과 같은 확률 표현은 사용하지 마십시오: "KEV에 등재될 확률 ...", "실제 공격이 발생할 확률 ...".
   - 권장 표현: "해당 취약점은 CVSS, EPSS, PoC, CWE 지표를 종합한 결과 높은 위험 점수로 산정되었습니다."
                 KEV 인 경우: "KEV 등재 취약점으로 threat_score 가 100점으로 설정되었습니다."
7. weight_detail 의 각 항목 기여도(cvss_contribution / epss_contribution / poc_contribution / cwe_contribution)
   를 활용해 "왜 이 점수가 높은가" 를 설명할 수 있습니다.
   weight_detail.auxiliary_comparison 의 LeeWonGi 결과는 보조 비교용으로만 참고하며,
   final_risk_score 를 덮어쓰지 마십시오.
8. 보안 관리자(SOC/CISO 산하 인력)가 곧바로 읽을 수 있는 단문/객관 톤으로 작성하십시오.
9. report_text 필드는 Markdown 형식으로 작성하되, 헤더는 H1/H2 만 사용하십시오.
"""

_SYSTEM_EN = """You are an AI security assistant for financial-sector analysts.
Your role is to write natural-language explanations and draft response guides based on
the already-computed Logistic-Regression-based threat_score.

[STRICT RULES]
1. Respond strictly in the specified JSON schema — no extra text.
2. Never fabricate facts that are not present in the input (e.g. patch URLs, exploit code).
3. If patch info is missing, only say "Refer to the official advisory and consider upgrading to the latest version."
4. The output is a "response guide draft" — explicitly note that final security actions require analyst review.
5. **Never recalculate the risk score.** Only cite final_risk_score / risk_level / priority / weight_detail as given.
6. Score interpretation:
   - The risk score is a Logistic-Regression-based threat_score (0~100).
     If the CVE is listed in KEV, the score is overridden to 100.
   - Tiers: 100 → Immediate, ≥84.4 → High, ≥24.3 → Medium, <24.3 → Low.
   - Do NOT phrase results as a probability. Forbidden: "probability of KEV listing", "likelihood of exploitation".
   - Preferred phrasing: "Given the CVSS / EPSS / PoC / CWE indicators, this vulnerability received a high threat_score."
                          For KEV: "Listed in KEV — threat_score overridden to 100."
7. Use weight_detail.{cvss,epss,poc,cwe}_contribution to explain WHY the score is high.
   weight_detail.auxiliary_comparison (LeeWonGi) is for reference only; never override final_risk_score with it.
8. Use a concise, objective tone suitable for SOC/CISO staff.
9. The report_text field must be Markdown using only H1/H2 headers.
"""

_SYSTEM_ZH = """你是金融行业安全分析师的 AI 安全助手。
你的职责是基于已经计算完成的 Logistic Regression threat_score（0~100），撰写自然语言解释和应对方案初稿。

[严格要求]
1. 必须严格按指定 JSON 模式返回，不得包含其他文本。
2. 不得编造输入中未提供的事实（如不存在的补丁链接、未验证的 PoC 等）。
3. 若输入未提供补丁信息，仅回复"建议查阅官方安全公告并考虑升级至最新版本"。
4. 输出为"应对指南草稿(draft)"，必须注明最终安全措施需由安全负责人审阅确认。
5. **严禁重新计算风险分数**，仅引用输入中的 final_risk_score / risk_level / priority / weight_detail。
6. 风险分数解释规则：
   - 风险分数为 Logistic Regression threat_score（0~100），CVE 已收录 KEV 时 override 为 100 分。
   - 分级：100 → Immediate，≥84.4 → High（高危），≥24.3 → Medium（潜在威胁），<24.3 → Low（可接受）。
   - 禁止使用概率措辞：「KEV 收录概率」「被实际攻击的概率」等。
   - 推荐措辞：「该漏洞综合 CVSS、EPSS、PoC、CWE 指标，得到较高的 threat_score」。
                若属 KEV：「该 CVE 已收录于 KEV，threat_score 被覆写为 100。」
7. 可使用 weight_detail 中 cvss_contribution / epss_contribution / poc_contribution / cwe_contribution 解释分数构成。
   weight_detail.auxiliary_comparison（LeeWonGi）仅作参考，不得覆盖 final_risk_score。
8. 使用简洁、客观、SOC/CISO 人员可直接阅读的语调。
9. report_text 字段使用 Markdown 格式，只用 H1/H2 标题。
"""


OUTPUT_SCHEMA = {
    "risk_summary": "string — 자산/취약점이 위험한 이유를 1~2 문장으로 요약",
    "risk_reasons": [
        "string — 위험 원인 1",
        "string — 위험 원인 2",
        "string — 위험 원인 3",
    ],
    "recommended_actions": [
        "string — 대응 방안 1",
        "string — 대응 방안 2",
        "string — 대응 방안 3",
    ],
    "priority": "Immediate | High | Medium | Low 중 하나",
    "report_text": "string — Dashboard 표시 및 보고서 출력용 Markdown 전문",
}


# ───────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────

def get_system_prompt(lang: str = "ko") -> str:
    return {"ko": _SYSTEM_KO, "en": _SYSTEM_EN, "zh": _SYSTEM_ZH}.get(lang, _SYSTEM_KO)


def build_vulnerability_prompt(input_data: dict, lang: str = "ko") -> str:
    """단일 자산-CVE 쌍에 대한 LLM 입력 Prompt 생성."""
    header = {
        "ko": "다음은 이미 계산된 취약점 분석 결과입니다. 위 규칙과 아래 JSON 스키마에 맞춰 보고서를 작성하십시오.",
        "en": "Below is an already-computed vulnerability analysis. Produce the report in the JSON schema below.",
        "zh": "以下是已计算完成的漏洞分析结果。请按以下 JSON 模式输出报告。",
    }[lang]
    return _compose(
        header,
        sections=[("입력 데이터", _sanitize(input_data))],
        lang=lang,
    )


def build_asset_prompt(asset_info: dict, vulns: list, lang: str = "ko") -> str:
    """단일 자산 내 다수 취약점 종합 보고서 Prompt."""
    header = {
        "ko": "다음 자산에 식별된 모든 취약점을 종합해 자산 단위 보고서를 작성하십시오.",
        "en": "Aggregate all vulnerabilities on this asset into a single asset-level report.",
        "zh": "请汇总该资产上所有已识别的漏洞，生成资产级报告。",
    }[lang]
    return _compose(
        header,
        sections=[
            ("자산 정보", _sanitize(asset_info)),
            (f"취약점 목록 ({len(vulns)}건)", [_sanitize(v) for v in vulns]),
        ],
        lang=lang,
    )


def build_summary_prompt(scan_meta: dict, top_vulns: list, lang: str = "ko") -> str:
    """전체 스캔 결과 임원 요약 보고서 Prompt."""
    header = {
        "ko": "전체 스캔 결과의 임원 보고용 요약을 작성하십시오. 핵심 자산/우선순위/대표 위협을 중심으로 정리하십시오.",
        "en": "Produce an executive summary of the full scan result, focusing on critical assets, priorities, and top threats.",
        "zh": "请生成本次全量扫描结果的高管摘要，聚焦关键资产、优先级与代表性威胁。",
    }[lang]
    return _compose(
        header,
        sections=[
            ("스캔 메타데이터", _sanitize(scan_meta)),
            (f"Top 취약점 ({len(top_vulns)}건)", [_sanitize(v) for v in top_vulns]),
        ],
        lang=lang,
    )


# ───────────────────────────────────────────────
# Internal
# ───────────────────────────────────────────────

def _compose(header: str, sections: list, lang: str) -> str:
    parts = [header, ""]
    for title, body in sections:
        parts.append(f"[{title}]")
        parts.append("```json")
        parts.append(json.dumps(body, ensure_ascii=False, indent=2))
        parts.append("```")
        parts.append("")
    parts.append("[필수 출력 JSON 스키마]")
    parts.append("```json")
    parts.append(json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2))
    parts.append("```")
    return "\n".join(parts)


def _sanitize(d):
    """JSON 직렬화 가능한 형태로 변환."""
    if isinstance(d, dict):
        return {k: _sanitize(v) for k, v in d.items()}
    if isinstance(d, (list, tuple, set)):
        return [_sanitize(v) for v in d]
    if isinstance(d, (str, int, float, bool)) or d is None:
        return d
    return str(d)

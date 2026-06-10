"""Risk Data Adapter — 논문 최종판.

[주 모델] 张正秀(JangJeongsoo) Logistic Regression 기반 threat_score
[보조 비교] 李元吉(LeeWonGi) 선형 결합 점수 (auxiliary_comparison 으로만 사용)

설계 원칙
─────────
1. LLM은 점수를 절대 재계산하지 않는다.
   이 어댑터가 산출한 final_risk_score / risk_level / weight_detail 만 LLM 에 전달한다.

2. final_risk_score 는 张正秀 LR 기반 threat_score 를 사용한다.
   - 단, CVE 가 KEV 에 등재되어 있다면 threat_score 를 100 으로 override 한다.

3. 李元吉 모델은 weight_detail.auxiliary_comparison 에 함께 표시되지만,
   final_risk_score / risk_level / priority 를 덮어쓰지 않는다.
"""
import math
import os
from typing import Iterable


# ═══════════════════════════════════════════════════════════════
# 张正秀 (JangJeongsoo) — 주 모델
# Logistic Regression 기반 위협도 점수 (논문 최종판)
#
# 1) 선형 결합:
#       score = bias + w1·CVSS + w2·EPSS + w3·PoC + w4·CWE
# 2) sigmoid:
#       prob = 1 / (1 + exp(-score))
# 3) threat_score = prob × 100
# 4) KEV 등재 시 threat_score = 100 (override)
#
# 분급:
#   100점        → Immediate (KEV)
#   84.4점 이상  → High      (고위험군)
#   24.3점 이상  → Medium    (잠재 위협)
#   24.3점 미만  → Low       (수용 가능 위협)
# ═══════════════════════════════════════════════════════════════

JANG_LR_COEF = {
    "bias": -5.9571,
    "base_cvss": 0.1744,
    "base_epss": 5.6841,   # EPSS percentile 기준
    "flag_poc": 0.7553,
    "flag_cwe": 0.2420,
}

JANG_BANK_CWES = {
    "CWE-89", "CWE-78", "CWE-287", "CWE-306", "CWE-502",
    "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-327",
    "CWE-326", "CWE-311", "CWE-918", "CWE-611", "CWE-434",
    "CWE-1104", "CWE-494",
}

# 분급 임계값 (논문 §3)
JANG_THRESHOLD_HIGH = 84.4
JANG_THRESHOLD_MEDIUM = 24.3


def _normalize_cwe_list(cwe) -> list:
    if cwe is None:
        return []
    if isinstance(cwe, str):
        return [c.strip() for c in cwe.split(",") if c.strip()]
    if isinstance(cwe, Iterable):
        return [str(c).strip() for c in cwe if str(c).strip()]
    return [str(cwe)]


def sigmoid(x: float) -> float:
    """수치 안정성을 보장한 sigmoid."""
    try:
        if x >= 0:
            z = math.exp(-x)
            return 1.0 / (1.0 + z)
        z = math.exp(x)
        return z / (1.0 + z)
    except OverflowError:
        return 0.0 if x < 0 else 1.0


def jang_lr_probability(cvss_score: float, epss_score: float,
                        poc_flag, cwe_flag) -> float:
    """张正秀 LR 확률(0~1).

    epss_score: 논문에서는 EPSS percentile 을 사용함.
    poc_flag / cwe_flag: 0 또는 1 (bool 도 허용).
    """
    z = (
        JANG_LR_COEF["bias"]
        + JANG_LR_COEF["base_cvss"] * float(cvss_score or 0)
        + JANG_LR_COEF["base_epss"] * float(epss_score or 0)
        + JANG_LR_COEF["flag_poc"] * int(bool(poc_flag))
        + JANG_LR_COEF["flag_cwe"] * int(bool(cwe_flag))
    )
    return sigmoid(z)


def jang_threat_score(cvss_score: float, epss_score: float,
                      poc_flag, cwe_flag, kev_status: bool = False) -> float:
    """张正秀 threat_score (0~100).

    KEV 등재 시 무조건 100 으로 override.
    그렇지 않으면 prob × 100 (소수점 둘째자리 반올림).
    """
    if kev_status:
        return 100.0
    prob = jang_lr_probability(cvss_score, epss_score, poc_flag, cwe_flag)
    return round(prob * 100, 2)


def jang_risk_level(threat_score: float) -> str:
    """threat_score(0~100) → 4-tier priority.

      100         → Immediate
      ≥ 84.4      → High
      ≥ 24.3      → Medium
      < 24.3      → Low
    """
    if threat_score >= 100:
        return "Immediate"
    if threat_score >= JANG_THRESHOLD_HIGH:
        return "High"
    if threat_score >= JANG_THRESHOLD_MEDIUM:
        return "Medium"
    return "Low"


# ═══════════════════════════════════════════════════════════════
# 李元吉 (LeeWonGi) — 보조 비교 (auxiliary_comparison)
#
# 산식: Score = w1·CVSS + w2·KEV + w3·CWE_bank + w4·EPSS_score
# 출처: Risk Analysis Module/Weight Tuning/LeeWonGi/weight_simulation.py
#       manual_weights = [1.00, 3.58, 5.36, 8.94]
#
# 본 모듈의 final_risk_score 는 张正秀 threat_score 가 결정하며,
# 李元吉 모델은 weight_detail.auxiliary_comparison 에 함께 노출되어 비교 분석에만 사용된다.
# ═══════════════════════════════════════════════════════════════

LEE_WEIGHTS = {
    "cvss": 1.00,
    "kev": 3.58,
    "cwe_bank": 5.36,
    "epss": 8.94,
}

LEE_BANK_CWES = {
    "CWE-190", "CWE-639", "CWE-306", "CWE-287", "CWE-613",
    "CWE-89", "CWE-311", "CWE-918", "CWE-117", "CWE-330",
}


def lee_score(cvss: float, in_kev: bool, cwe_ids, epss: float) -> float:
    """李元吉 선형 결합 점수 (보조 비교용).

    `epss` 는 원본 weight_simulation.py 와 동일하게 epss_score 값을 받는다.
    (호출자가 epss_score 가 없으면 epss_percentile 로 fallback 후 전달할 것)
    """
    cwes = _normalize_cwe_list(cwe_ids)
    cwe_match = 1.0 if any(c in LEE_BANK_CWES for c in cwes) else 0.0
    return (
        float(cvss or 0) * LEE_WEIGHTS["cvss"]
        + (1.0 if in_kev else 0.0) * LEE_WEIGHTS["kev"]
        + cwe_match * LEE_WEIGHTS["cwe_bank"]
        + float(epss or 0) * LEE_WEIGHTS["epss"]
    )


def lee_risk_level(score: float) -> str:
    """李元吉 점수 기반 4-tier (보조 비교용).

    원본 weight_simulation.py 의 CRITICAL/WARNING/INFO 는 순위 기반이지만,
    단건 평가용으로 점수 기반 임계값으로 변환.
    """
    if score >= 18.0:
        return "Immediate"
    if score >= 12.0:
        return "High"
    if score >= 6.0:
        return "Medium"
    return "Low"


# ═══════════════════════════════════════════════════════════════
# LLM 입력 dict 생성
# ═══════════════════════════════════════════════════════════════

def build_llm_input(record: dict) -> dict:
    """OpenSearch + scan_report 병합 레코드를 LLM 입력 dict로 변환.

    final_risk_score = 张正秀 threat_score (KEV 시 100 override)
    risk_level / priority 도 张正秀 결과로 결정.
    李元吉 결과는 weight_detail.auxiliary_comparison 에만 노출.
    """
    cvss = float(record.get("cvss_score") or 0.0)

    # EPSS — 두 모델 모두 입력으로 사용.
    #   - 张正秀(논문): epss_percentile (없으면 epss_score 로 fallback)
    #   - 李元吉(원본): epss_score (없으면 epss_percentile 로 fallback)
    epss_score_val = record.get("epss_score")
    epss_pct_val = record.get("epss_percentile")
    epss_for_jang = float(epss_pct_val) if epss_pct_val is not None else float(epss_score_val or 0.0)
    epss_for_lee = float(epss_score_val) if epss_score_val is not None else float(epss_pct_val or 0.0)
    lee_used_fallback = epss_score_val is None and epss_pct_val is not None

    in_kev = bool(record.get("in_kev", False))
    cwe_ids = _normalize_cwe_list(record.get("cwe_ids") or record.get("cwes"))
    has_poc_raw = record.get("has_poc")
    has_poc = bool(has_poc_raw) if has_poc_raw is not None else False

    # Flag 값들
    cwe_flag_jang = 1 if any(c in JANG_BANK_CWES for c in cwe_ids) else 0
    cwe_bank_flag_lee = 1 if any(c in LEE_BANK_CWES for c in cwe_ids) else 0
    poc_flag = 1 if has_poc else 0
    kev_flag = 1 if in_kev else 0

    # ── 주 모델: 张正秀 LR threat_score ──
    threat_score = jang_threat_score(cvss, epss_for_jang, poc_flag, cwe_flag_jang, kev_status=in_kev)
    risk_level = jang_risk_level(threat_score)

    # KEV override 가 발생했을 때의 raw 확률/점수도 같이 노출 (디버그/분석용)
    raw_prob = jang_lr_probability(cvss, epss_for_jang, poc_flag, cwe_flag_jang)
    raw_threat_score = round(raw_prob * 100, 2)

    # 항목별 기여도 (선형 결합부 — sigmoid 이전 단계)
    jang_contribution = {
        "cvss_contribution": round(JANG_LR_COEF["base_cvss"] * cvss, 4),
        "epss_contribution": round(JANG_LR_COEF["base_epss"] * epss_for_jang, 4),
        "poc_contribution": round(JANG_LR_COEF["flag_poc"] * poc_flag, 4),
        "cwe_contribution": round(JANG_LR_COEF["flag_cwe"] * cwe_flag_jang, 4),
        "bias": JANG_LR_COEF["bias"],
    }

    # ── 보조 모델: 李元吉 선형 점수 ──
    lee = lee_score(cvss, in_kev, cwe_ids, epss_for_lee)
    lee_lvl = lee_risk_level(lee)
    lee_contribution = {
        "cvss_contribution": round(LEE_WEIGHTS["cvss"] * cvss, 4),
        "kev_contribution": round(LEE_WEIGHTS["kev"] * kev_flag, 4),
        "cwe_contribution": round(LEE_WEIGHTS["cwe_bank"] * cwe_bank_flag_lee, 4),
        "epss_contribution": round(LEE_WEIGHTS["epss"] * epss_for_lee, 4),
    }

    # ── ranking_reason: 주 모델(Jang) 기여도 기준 ──
    contrib_for_reason = {
        "CVSS": jang_contribution["cvss_contribution"],
        "EPSS": jang_contribution["epss_contribution"],
        "PoC": jang_contribution["poc_contribution"],
        "CWE": jang_contribution["cwe_contribution"],
    }
    sorted_contrib = sorted(contrib_for_reason.items(), key=lambda x: -x[1])
    reason_parts = [f"{k} 기여도 {v:+.4f}" for k, v in sorted_contrib if abs(v) > 0.0001]
    if in_kev:
        reason_parts.insert(0, "KEV 등재 → threat_score=100 override")
    ranking_reason = " | ".join(reason_parts) if reason_parts else "기여도 없음"

    return {
        "asset_id": record.get("asset_id")
                    or record.get("host")
                    or record.get("domain")
                    or "",
        "domain": record.get("domain") or record.get("root_domain") or "",
        "ip": record.get("ip") or record.get("host") or "",
        "port": record.get("port"),
        "service_name": record.get("service") or record.get("service_name") or "",
        "technology_stack": record.get("technologies")
                            or record.get("matched_technology")
                            or [],
        "cve_id": record.get("cve_id"),
        "cvss_score": cvss,
        "epss_score": float(epss_score_val) if epss_score_val is not None else None,
        "epss_percentile": float(epss_pct_val) if epss_pct_val is not None else None,
        "kev_status": in_kev,
        "poc_status": has_poc if has_poc_raw is not None else None,
        "cwe_id": cwe_ids,
        "final_risk_score": threat_score,
        "risk_level": risk_level,
        "priority": risk_level,
        "ranking_reason": ranking_reason,
        "weight_detail": {
            "primary_model": "JangJeongsoo Logistic Regression (threat_score)",
            "formula": "threat_score = sigmoid(bias + w1*CVSS + w2*EPSS + w3*PoC + w4*CWE) * 100",
            "kev_override_rule": "in_kev == True → threat_score = 100",
            "thresholds": {
                "immediate": 100,
                "high": JANG_THRESHOLD_HIGH,
                "medium": JANG_THRESHOLD_MEDIUM,
            },
            "coefficients": JANG_LR_COEF,
            "cvss_contribution": jang_contribution["cvss_contribution"],
            "epss_contribution": jang_contribution["epss_contribution"],
            "poc_contribution": jang_contribution["poc_contribution"],
            "cwe_contribution": jang_contribution["cwe_contribution"],
            "raw_probability": round(raw_prob, 6),
            "raw_threat_score_before_kev_override": raw_threat_score,
            "kev_overridden": in_kev,
            "auxiliary_comparison": {
                "model": "LeeWonGi Linear Weighted Score",
                "source": "Risk Analysis Module/Weight Tuning/LeeWonGi/weight_simulation.py",
                "formula": "Score = w1*CVSS + w2*KEV + w3*CWE + w4*EPSS_score",
                "weights": LEE_WEIGHTS,
                "epss_input": "epss_score" if not lee_used_fallback else "epss_percentile (fallback)",
                "score": round(lee, 4),
                "level": lee_lvl,
                "cvss_contribution": lee_contribution["cvss_contribution"],
                "kev_contribution": lee_contribution["kev_contribution"],
                "cwe_contribution": lee_contribution["cwe_contribution"],
                "epss_contribution": lee_contribution["epss_contribution"],
                "note": "final_risk_score 를 덮어쓰지 않으며 비교 분석용으로만 제공됨",
            },
        },
    }


# ═══════════════════════════════════════════════════════════════
# OpenSearch 직접 조회 (선택적)
# ═══════════════════════════════════════════════════════════════

def load_record_from_opensearch(cve_id: str, asset_info: dict = None) -> dict:
    """OpenSearch에서 CVE 1건을 조회해 자산 정보(asset_info)와 병합한 record를 반환."""
    try:
        from opensearchpy import OpenSearch
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError as e:
        raise RuntimeError("opensearch-py 미설치. requirements.txt 설치 필요.") from e

    client = OpenSearch(
        hosts=[{
            "host": os.getenv("OPENSEARCH_HOST", "localhost"),
            "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
        }],
        http_auth=(
            os.getenv("OPENSEARCH_USER", "admin"),
            os.getenv("OPENSEARCH_PASSWORD", "VulnScanner_2026!@#"),
        ),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
    )
    res = client.search(
        index="vulnerability_cve",
        body={"query": {"term": {"cve_id": cve_id}}, "size": 1},
    )
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        raise LookupError(f"CVE {cve_id} not found in OpenSearch")
    src = dict(hits[0]["_source"])
    if asset_info:
        for k, v in asset_info.items():
            if v not in (None, "", [], {}):
                src[k] = v
    return src

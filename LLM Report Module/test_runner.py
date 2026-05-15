"""LLM Report Module 단위 테스트 (Mock Provider 기준, 논문 최종판).

실행:
  cd "LLM Report Module"
  python test_runner.py

이 테스트는 OpenSearch / 실제 LLM API 에 의존하지 않는다.

검증 범위
─────────
- 张正秀 Logistic Regression threat_score 계산 (sigmoid 기반)
- KEV 등재 시 threat_score = 100 override
- threat_score 기반 4-tier 분급 (Immediate / High / Medium / Low)
- 李元吉 모델이 auxiliary_comparison 에 포함되는지
- Mock LLM Provider 가 JSON 보고서를 정상 반환하는지
"""
import json
import os

os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("REPORT_LANGUAGE", "ko")

from llm_report_generator import LLMReportGenerator
from risk_data_adapter import (
    build_llm_input,
    jang_lr_probability,
    jang_threat_score,
    jang_risk_level,
    lee_score,
    sigmoid,
)


# ───────────────────────────────────────────────
# [0] 핵심 점수 함수 단위 테스트
# ───────────────────────────────────────────────

def test_sigmoid():
    print("\n[0/6] sigmoid 함수")
    print("─" * 70)
    assert abs(sigmoid(0) - 0.5) < 1e-9
    assert sigmoid(100) > 0.999
    assert sigmoid(-100) < 0.001
    print(" sigmoid(0)=0.5, sigmoid(100)≈1, sigmoid(-100)≈0  [OK]")


def test_jang_threat_score_non_kev():
    print("\n[1/6] 非 KEV 취약점의 threat_score 계산 (CVE-2021-44228 Log4Shell)")
    print("─" * 70)
    # CVE-2021-44228: CVSS=10.0, EPSS_pct=0.99, PoC=1, CWE=1
    prob = jang_lr_probability(10.0, 0.99, 1, 1)
    ts = jang_threat_score(10.0, 0.99, 1, 1, kev_status=False)
    expected_z = -5.9571 + 0.1744 * 10 + 5.6841 * 0.99 + 0.7553 + 0.2420
    expected_prob = 1.0 / (1.0 + pow(2.718281828, -expected_z))
    print(f" z = {expected_z:.4f}")
    print(f" prob = {prob:.6f} (expected ~{expected_prob:.6f})")
    print(f" threat_score = {ts}")
    assert abs(prob - expected_prob) < 1e-4, f"prob 계산 오차: {prob} vs {expected_prob}"
    assert ts == round(prob * 100, 2)
    assert ts < 100.0, "비-KEV 인데 100점이 나오면 안 됨"
    print(" [OK]")


def test_jang_threat_score_kev_override():
    print("\n[2/6] KEV override → threat_score = 100")
    print("─" * 70)
    # 어떤 입력이든 KEV=True 면 100
    ts1 = jang_threat_score(0.0, 0.0, 0, 0, kev_status=True)
    ts2 = jang_threat_score(3.5, 0.10, 0, 0, kev_status=True)
    ts3 = jang_threat_score(10.0, 0.99, 1, 1, kev_status=True)
    print(f" KEV(0,0,0,0)    = {ts1}")
    print(f" KEV(3.5,0.1,0,0)= {ts2}")
    print(f" KEV(10,0.99,1,1)= {ts3}")
    assert ts1 == 100.0
    assert ts2 == 100.0
    assert ts3 == 100.0
    print(" [OK]")


def test_jang_risk_level_thresholds():
    print("\n[3/6] threat_score → risk_level 분급 (100 / 84.4 / 24.3)")
    print("─" * 70)
    cases = [
        (100.0, "Immediate"),
        (90.0,  "High"),
        (84.4,  "High"),
        (84.39, "Medium"),
        (50.0,  "Medium"),
        (24.3,  "Medium"),
        (24.29, "Low"),
        (10.0,  "Low"),
        (0.0,   "Low"),
    ]
    for ts, expected in cases:
        actual = jang_risk_level(ts)
        marker = "OK" if actual == expected else "FAIL"
        print(f"  threat_score={ts:6.2f} → {actual:<9} (expected {expected:<9}) [{marker}]")
        assert actual == expected, f"{ts} 분급 실패: {actual} vs {expected}"
    print(" [OK]")


# ───────────────────────────────────────────────
# [4] build_llm_input — 통합 입력 빌더
# ───────────────────────────────────────────────

SAMPLE_NON_KEV = {
    "asset_id": "asset-002",
    "domain": "example.com",
    "ip": "10.0.0.5",
    "host": "example.com",
    "port": 443,
    "service": "https",
    "technologies": ["nginx:1.18.0"],
    "cve_id": "CVE-2099-FAKE",
    "cvss_score": 7.5,
    "epss_score": 0.40,
    "epss_percentile": 0.60,
    "in_kev": False,
    "has_poc": False,
    "cwe_ids": ["CWE-200"],  # Lee/Jang BANK 모두 미포함
}

SAMPLE_KEV = {
    "asset_id": "asset-001",
    "domain": "localhost",
    "ip": "127.0.0.1",
    "host": "localhost",
    "port": 8080,
    "service": "http",
    "technologies": ["apache:log4j-core:2.14.1"],
    "cve_id": "CVE-2021-44228",
    "cvss_score": 10.0,
    "epss_score": 0.97,
    "epss_percentile": 0.99,
    "in_kev": True,
    "has_poc": True,
    "cwe_ids": ["CWE-502", "CWE-917"],   # CWE-502 ∈ JANG_BANK_CWES
}


def test_build_llm_input_non_kev():
    print("\n[4/6] build_llm_input — 非 KEV 취약점")
    print("─" * 70)
    d = build_llm_input(SAMPLE_NON_KEV)
    print(f" final_risk_score = {d['final_risk_score']}")
    print(f" risk_level       = {d['risk_level']}")
    print(f" priority         = {d['priority']}")
    print(f" weight_detail.primary_model = {d['weight_detail']['primary_model']}")
    print(f" weight_detail.kev_overridden = {d['weight_detail']['kev_overridden']}")
    print(f" auxiliary(Lee).score = {d['weight_detail']['auxiliary_comparison']['score']}")

    assert d["kev_status"] is False
    assert d["weight_detail"]["kev_overridden"] is False
    assert 0 <= d["final_risk_score"] < 100, "비-KEV 인데 100 이 나오면 안 됨"
    assert d["risk_level"] in {"Low", "Medium", "High"}
    assert d["priority"] == d["risk_level"]
    assert "auxiliary_comparison" in d["weight_detail"]
    print(" [OK]")


def test_build_llm_input_kev():
    print("\n[5/6] build_llm_input — KEV 취약점")
    print("─" * 70)
    d = build_llm_input(SAMPLE_KEV)
    print(f" final_risk_score = {d['final_risk_score']}")
    print(f" risk_level       = {d['risk_level']}")
    print(f" weight_detail.kev_overridden = {d['weight_detail']['kev_overridden']}")
    print(f" raw(non-override) threat_score = {d['weight_detail']['raw_threat_score_before_kev_override']}")
    print(f" auxiliary(Lee).score = {d['weight_detail']['auxiliary_comparison']['score']}")

    assert d["kev_status"] is True
    assert d["weight_detail"]["kev_overridden"] is True
    assert d["final_risk_score"] == 100.0
    assert d["risk_level"] == "Immediate"
    # auxiliary 가 final 을 덮어쓰지 않는지 (Lee 점수와 final 이 다른지)
    aux = d["weight_detail"]["auxiliary_comparison"]
    assert aux["score"] != d["final_risk_score"], "auxiliary 가 final 을 덮어쓴 것으로 보입니다."
    print(" [OK]")


# ───────────────────────────────────────────────
# [6] Mock LLM Provider — 최종 보고서 JSON
# ───────────────────────────────────────────────

def test_mock_llm_report():
    print("\n[6/6] Mock LLM Provider — 보고서 JSON 생성")
    print("─" * 70)
    gen = LLMReportGenerator()

    # KEV 케이스
    inp_kev = build_llm_input(SAMPLE_KEV)
    rep_kev = gen.generate_vulnerability_report(inp_kev)
    assert {"risk_summary", "risk_reasons", "recommended_actions", "priority", "report_text"} <= rep_kev.keys()
    assert rep_kev["priority"] in {"Immediate", "High", "Medium", "Low"}
    print(f" [KEV] priority={rep_kev['priority']}, summary={rep_kev['risk_summary'][:60]}...")

    # 非 KEV 케이스
    inp_non = build_llm_input(SAMPLE_NON_KEV)
    rep_non = gen.generate_vulnerability_report(inp_non)
    assert {"risk_summary", "risk_reasons", "recommended_actions", "priority", "report_text"} <= rep_non.keys()
    print(f" [non-KEV] priority={rep_non['priority']}, summary={rep_non['risk_summary'][:60]}...")

    # asset / summary 보고서도 동작 확인
    asset_rep = gen.generate_asset_report(
        {"asset_id": "asset-001", "host": "localhost", "port": 8080},
        [inp_kev, inp_non],
    )
    assert "report_text" in asset_rep

    summary_rep = gen.generate_summary_report(
        {"root_domain": "localhost", "scan_time": "2026-04-09", "total_assets": 1, "total_vulns": 2},
        [inp_kev, inp_non],
    )
    assert "report_text" in summary_rep
    print(" Mock Provider — vulnerability / asset / summary 보고서 모두 정상 반환 [OK]")


if __name__ == "__main__":
    test_sigmoid()
    test_jang_threat_score_non_kev()
    test_jang_threat_score_kev_override()
    test_jang_risk_level_thresholds()
    test_build_llm_input_non_kev()
    test_build_llm_input_kev()
    test_mock_llm_report()
    print("\n" + "█" * 70)
    print("  ✅ 전체 테스트 통과 (논문 최종판 / Mock Provider)")
    print("█" * 70)

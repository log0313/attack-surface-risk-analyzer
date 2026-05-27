"""Risk Data Adapter (LLM 입력 통제 최적화).
내부 변수(점수, 클러스터링 등)를 배제하고, 오직 식별자(CVE, CWE)만 추출합니다.
금융권 타겟 CWE 상수 목록을 관리합니다.
"""
from typing import Iterable

# 금융권 치명적 위협 CWE (SQLi, XSS, Deserialization, Auth bypass 등)
FINANCIAL_TARGET_CWES = [
    "CWE-89", "CWE-78", "CWE-287", "CWE-306", "CWE-502",
    "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-327",
    "CWE-326", "CWE-311", "CWE-918", "CWE-611", "CWE-434",
    "CWE-1104", "CWE-494", "CWE-79"
]

def _normalize_cwe_list(cwe) -> list:
    """다양한 형태의 CWE 입력을 리스트로 통일합니다."""
    if cwe is None:
        return []
    if isinstance(cwe, str):
        return [c.strip() for c in cwe.split(",") if c.strip()]
    if isinstance(cwe, Iterable):
        return [str(c).strip() for c in cwe if str(c).strip()]
    return [str(cwe)]

def build_llm_cve_list(raw_records: list) -> list:
    """스캐너의 Raw JSON 리스트에서 LLM 프롬프트에 들어갈 필수 항목만 필터링합니다."""
    cve_list = []

    for record in raw_records:
        cve_id = record.get("cve_id")
        if not cve_id:
            continue

        cwe_ids = _normalize_cwe_list(
            record.get("cwe_ids") or record.get("cwes") or record.get("cwe_id")
        )

        cve_list.append({
            "cve_id": cve_id,
            "cwe_ids": cwe_ids
        })

    return cve_list

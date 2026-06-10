"""유저 프롬프트 체크용 파일"""
from prompt_templates import build_vulnerability_prompt
from risk_data_adapter import FINANCIAL_TARGET_CWES, build_llm_cve_list

DB_RECORDS_MOCK = [
    {
        "cve_id": "CVE-2021-44228",
        "cwes": ["CWE-502"],
        "cvss_score": 10.0,  # 어댑터에 의해 무시됨
        "epss_percentile": 0.97
    },
    {
        "cve_id": "CVE-2024-XXXX",
        "cwes": ["CWE-79"],  # XSS (금융권 타겟)
        "has_poc": True
    },
    {
        "cve_id": "CVE-2014-0160",
        "cwes": ["CWE-119"],  # 비 타겟 CWE 예시
    },
    {
        "cve_id": "CVE-2021-44228",
        "cwes": ["CWE-917", "CWE-20", "CWE-400", "CWE-502"],  # 다중 CWE, 금융권 타겟 포함
    }
]

if __name__ == "__main__":
    cve_list = build_llm_cve_list(DB_RECORDS_MOCK)
    print(cve_list)
    user_prompt = build_vulnerability_prompt(FINANCIAL_TARGET_CWES, cve_list)
    print(user_prompt)


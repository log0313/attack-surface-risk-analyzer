import os
import json
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 본인의 api로 변경
os.environ["GEMINI_API_KEY"] = "AIxxxxxxx..."

from risk_data_adapter import build_llm_cve_list, FINANCIAL_TARGET_CWES
from llm_report_generator import LLMReportGenerator

# 가상의 스캐너 출력 데이터 세트
# (내부적으로 점수 로직이 있더라도, 어댑터가 알아서 걸러냅니다)
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


def run_integration_pipeline():
    try:
        generator = LLMReportGenerator(provider_name="gemini")
    except Exception as e:
        print(e)
        return

    # 1. 어댑터에서 LLM에게 던져줄 핵심 데이터(CVE, CWE)만 추출
    cve_list_for_llm = build_llm_cve_list(DB_RECORDS_MOCK)
    print(f"총 {len(cve_list_for_llm)}개의 CVE가 식별되었습니다. 단일 API 호출로 묶어서 전송합니다.")

    print("api 호출...")

    try:
        # 2. 1번의 호출로 전체 결과 생성
        report_output = generator.generate_reports(
            target_cwes=FINANCIAL_TARGET_CWES,
            cve_list=cve_list_for_llm
        )

        print("\n" + "─" * 80)
        print(json.dumps(report_output, ensure_ascii=False, indent=2))
        print("─" * 80)

    except Exception as e:
        print(f"에러 발생. 보고서 생성 실패: {e}")

if __name__ == "__main__":
    run_integration_pipeline()

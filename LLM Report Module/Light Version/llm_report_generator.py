"""LLM Report Generator (다중 CVE 일괄 생성 및 파싱)."""
import json
from llm_providers import get_provider
from prompt_templates import get_system_prompt, build_vulnerability_prompt

class LLMReportGenerator:
    def __init__(self, provider_name: str = "gemini"):
        self.provider = get_provider(provider_name)
        self.system_prompt = get_system_prompt()

    def generate_reports(self, target_cwes: list, cve_list: list) -> dict:
        """
        다수의 CVE 리스트를 한 번의 API 호출로 처리하여 JSON 보고서를 반환합니다.

        :param target_cwes: 강조해야 할 주요 CWE 목록 (list of str)
        :param cve_list: [{'cve_id': '...', 'cwe_ids': [...]}] 형태의 리스트
        :return: 파싱된 결과 dict ({"reports": [...]})
        """
        if not cve_list:
            return {"reports": []}

        # 1. 시스템 프롬프트 및 사용자 프롬프트 조합
        user_prompt = build_vulnerability_prompt(target_cwes, cve_list)

        # 2. LLM 호출
        raw_response = self.provider.generate(prompt=user_prompt, system=self.system_prompt)

        # 3. JSON 파싱
        try:
            return json.loads(raw_response)
        except json.JSONDecodeError as e:
            # 파싱 실패 시 원본 문자열을 남겨 디버깅을 돕습니다.
            raise RuntimeError(f"[JSON 파싱 실패] 원본 응답:\n{raw_response}") from e




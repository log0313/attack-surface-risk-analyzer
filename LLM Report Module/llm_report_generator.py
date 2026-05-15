"""LLM Report Generator — 핵심 모듈.

이미 산출된 위험 분석 결과(dict)를 받아 LLM Provider에 넘겨 자연어 보고서를 생성한다.
LLM은 final_risk_score / risk_level / priority 를 재계산하지 않으며,
이 모듈에서도 점수 재계산 로직은 일체 포함하지 않는다.
"""
import json
import os
import re

from llm_providers import get_provider
from prompt_templates import (
    build_asset_prompt,
    build_summary_prompt,
    build_vulnerability_prompt,
    get_system_prompt,
)


REQUIRED_KEYS = {
    "risk_summary",
    "risk_reasons",
    "recommended_actions",
    "priority",
    "report_text",
}

VALID_PRIORITIES = {"Immediate", "High", "Medium", "Low"}

_PRIORITY_ALIASES = {
    # Korean
    "긴급": "Immediate", "즉시": "Immediate",
    "높음": "High", "중간": "Medium", "보통": "Medium", "낮음": "Low",
    # English
    "critical": "Immediate", "immediate": "Immediate",
    "high": "High", "medium": "Medium", "low": "Low",
    # 内部 분류
    "confirmed": "Immediate", "warning": "High", "info": "Low",
    # Chinese
    "紧急": "Immediate", "高": "High", "中": "Medium", "低": "Low",
}


class LLMReportGenerator:
    def __init__(self, provider_name: str = "", lang: str = ""):
        self.provider = get_provider(provider_name)
        self.lang = (lang or os.getenv("REPORT_LANGUAGE", "ko")).lower()
        if self.lang not in {"ko", "en", "zh"}:
            self.lang = "ko"

    # ── Public API ──

    def generate_vulnerability_report(self, input_data: dict) -> dict:
        prompt = build_vulnerability_prompt(input_data, lang=self.lang)
        return self._invoke(prompt)

    def generate_asset_report(self, asset_info: dict, vulns: list) -> dict:
        prompt = build_asset_prompt(asset_info, vulns, lang=self.lang)
        return self._invoke(prompt)

    def generate_summary_report(self, scan_meta: dict, top_vulns: list) -> dict:
        prompt = build_summary_prompt(scan_meta, top_vulns, lang=self.lang)
        return self._invoke(prompt)

    # ── Internal ──

    def _invoke(self, prompt: str) -> dict:
        system = get_system_prompt(self.lang)
        raw = self.provider.generate(prompt, system=system)
        parsed = self._safe_parse(raw)
        self._validate(parsed)
        return parsed

    @staticmethod
    def _safe_parse(text: str) -> dict:
        text = (text or "").strip()
        if not text:
            raise ValueError("LLM 응답이 비어 있습니다.")

        # ```json ... ``` 코드 블록 우선 추출
        m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if m:
            text = m.group(1)

        # 첫 { 부터 마지막 } 까지 fallback
        if not text.startswith("{"):
            i, j = text.find("{"), text.rfind("}")
            if i >= 0 and j > i:
                text = text[i:j + 1]

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM 응답을 JSON으로 파싱하지 못했습니다: {e}") from e

    @staticmethod
    def _validate(data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError("LLM 응답이 JSON 객체가 아닙니다.")

        missing = REQUIRED_KEYS - set(data.keys())
        if missing:
            raise ValueError(f"필수 키 누락: {sorted(missing)}")

        # priority 정규화
        prio = str(data.get("priority", "")).strip()
        if prio not in VALID_PRIORITIES:
            data["priority"] = _PRIORITY_ALIASES.get(prio.lower(), "Medium")

        # 리스트 필드 보정
        for list_key in ("risk_reasons", "recommended_actions"):
            v = data.get(list_key)
            if not isinstance(v, list):
                data[list_key] = [str(v)] if v else []
            else:
                data[list_key] = [str(x) for x in v]

        # 문자열 필드 보정
        for str_key in ("risk_summary", "report_text"):
            v = data.get(str_key)
            if not isinstance(v, str):
                data[str_key] = json.dumps(v, ensure_ascii=False) if v else ""

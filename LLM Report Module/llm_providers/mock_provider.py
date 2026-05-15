"""Mock LLM Provider — API 키 없이 동작하는 개발/테스트용 Provider."""
import json
import re

from .base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    """Prompt에서 핵심 필드를 추출해 고정 형식 JSON을 만들어 반환한다.

    실제 LLM이 아니므로 자연어 품질은 떨어지지만,
    필드 누락 / 스키마 위반 / Pipeline 동작 테스트에는 충분하다.
    """

    name = "mock"

    def generate(self, prompt: str, system: str = "", **kwargs) -> str:
        cve_id = self._extract(prompt, "cve_id") or "UNKNOWN-CVE"
        host = (
            self._extract(prompt, "domain")
            or self._extract(prompt, "ip")
            or self._extract(prompt, "asset_id")
            or "unknown-host"
        )
        port = self._extract(prompt, "port") or "0"
        score = self._extract(prompt, "final_risk_score") or "N/A"
        level = self._extract(prompt, "risk_level") or "Medium"
        priority_field = self._extract(prompt, "priority") or level

        in_kev = "true" in (self._extract(prompt, "kev_status") or "").lower()
        epss = self._extract(prompt, "epss_percentile") or "0.0"
        cvss = self._extract(prompt, "cvss_score") or "0.0"

        priority_map = {
            "critical": "Immediate",
            "immediate": "Immediate",
            "confirmed": "Immediate",
            "high": "High",
            "warning": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Low",
        }
        priority = priority_map.get(str(priority_field).lower(), "Medium")

        reasons = []
        if in_kev:
            reasons.append("CISA KEV에 등재된 실제 악용 사례가 확인되었습니다.")
        try:
            if float(epss) >= 0.9:
                reasons.append(
                    f"EPSS percentile {epss}로 단기 내 익스플로잇 가능성이 매우 높습니다."
                )
        except ValueError:
            pass
        try:
            if float(cvss) >= 9.0:
                reasons.append(f"CVSS {cvss}로 심각도 등급이 최상위 구간입니다.")
        except ValueError:
            pass
        reasons.append(
            f"{host}:{port}는 외부 노출 자산이며, 패치 적용 우선순위가 높습니다."
        )
        if len(reasons) < 3:
            reasons.append(
                "동일 자산 내 다른 취약점과의 연쇄 공격 가능성을 함께 검토해야 합니다."
            )

        actions = [
            "공식 보안 권고문 및 패치 버전을 확인하여 적용을 검토하십시오.",
            f"포트 {port}의 외부 노출 여부를 재점검하고, 필요 시 WAF 룰 또는 접근 제어를 적용하십시오.",
            "최근 30일 액세스 로그를 분석해 익스플로잇 시도 흔적이 있는지 조사하십시오.",
        ]

        result = {
            "risk_summary": (
                f"[MOCK] {cve_id}는 {host}:{port}에서 식별된 위험도 {level}의 취약점으로, "
                f"최종 위험 점수는 {score}입니다."
            ),
            "risk_reasons": reasons[:3],
            "recommended_actions": actions,
            "priority": priority,
            "report_text": (
                f"# AI 위험 분석 보고서 (Mock)\n\n"
                f"- 대상 자산: {host}:{port}\n"
                f"- 취약점: {cve_id}\n"
                f"- 최종 위험 점수: {score} ({level})\n"
                f"- 대응 우선순위: {priority}\n\n"
                f"## 위험 원인\n"
                + "\n".join(f"- {r}" for r in reasons[:3])
                + "\n\n## 대응 방안\n"
                + "\n".join(f"- {a}" for a in actions)
                + "\n\n> 본 보고서는 Mock Provider가 생성한 샘플입니다. "
                "실제 보안 명령으로 사용하기 전 보안 관리자의 검토가 필요합니다."
            ),
        }
        return json.dumps(result, ensure_ascii=False)

    @staticmethod
    def _extract(prompt: str, key: str) -> str:
        # 1) JSON 스타일: "key": value
        m = re.search(rf'"{re.escape(key)}"\s*:\s*"?([^",\n}}\]]+)', prompt)
        if m:
            return m.group(1).strip().rstrip('"')
        # 2) plain text: key: value
        m = re.search(rf"{re.escape(key)}\s*[:=]\s*([^\n,]+)", prompt, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return ""

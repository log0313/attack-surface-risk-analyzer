"""LLM Provider 추상 베이스 클래스."""
from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """모든 LLM Provider가 구현해야 하는 인터페이스."""

    name: str = "base"

    @abstractmethod
    def generate(self, prompt: str, system: str = "", **kwargs) -> str:
        """Prompt를 받아 LLM 응답 텍스트를 반환한다.

        반환값은 항상 문자열이며, JSON 파싱은 호출자(LLMReportGenerator)가 담당한다.
        """
        raise NotImplementedError

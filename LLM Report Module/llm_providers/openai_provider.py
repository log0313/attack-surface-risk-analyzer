"""OpenAI API Provider — 실제 LLM 호출 (선택적).

OPENAI_API_KEY 가 .env 에 설정되어 있어야 한다.
"""
import os

from .base import BaseLLMProvider


class OpenAIProvider(BaseLLMProvider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY가 설정되지 않았습니다. "
                ".env 파일을 확인하거나 LLM_PROVIDER=mock 으로 전환하십시오."
            )
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError(
                "openai 라이브러리가 설치되지 않았습니다. `pip install openai`"
            ) from e
        self.client = OpenAI(api_key=api_key)
        self.model = os.getenv("OPENAI_MODEL", model)

    def generate(self, prompt: str, system: str = "", **kwargs) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.2),
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content or ""

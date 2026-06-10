"""Anthropic Claude Provider (선택적)."""
import os

from .base import BaseLLMProvider


class ClaudeProvider(BaseLLMProvider):
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-4-6"):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY가 설정되지 않았습니다.")
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("anthropic 미설치. `pip install anthropic`") from e
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = os.getenv("ANTHROPIC_MODEL", model)

    def generate(self, prompt: str, system: str = "", **kwargs) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", 2048),
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        if not resp.content:
            return ""
        return resp.content[0].text or ""

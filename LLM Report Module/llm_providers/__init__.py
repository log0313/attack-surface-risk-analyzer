"""LLM Provider 팩토리.

환경변수 LLM_PROVIDER 또는 호출 인자에 따라 Provider 인스턴스를 생성한다.
"""
import os

from .base import BaseLLMProvider
from .mock_provider import MockLLMProvider


def get_provider(name: str = "") -> BaseLLMProvider:
    name = (name or os.getenv("LLM_PROVIDER", "mock")).lower()

    if name == "mock":
        return MockLLMProvider()
    if name == "openai":
        from .openai_provider import OpenAIProvider
        return OpenAIProvider()
    if name == "gemini":
        from .gemini_provider import GeminiProvider
        return GeminiProvider()
    if name == "claude":
        from .claude_provider import ClaudeProvider
        return ClaudeProvider()

    raise ValueError(f"알 수 없는 LLM Provider: {name}")

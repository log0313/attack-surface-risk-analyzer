"""Google Gemini Provider (선택적)."""
import os

from .base import BaseLLMProvider


class GeminiProvider(BaseLLMProvider):
    name = "gemini"

    def __init__(self, model: str = "gemini-1.5-flash"):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY가 설정되지 않았습니다.")
        try:
            import google.generativeai as genai
        except ImportError as e:
            raise RuntimeError(
                "google-generativeai 미설치. `pip install google-generativeai`"
            ) from e
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", model))

    def generate(self, prompt: str, system: str = "", **kwargs) -> str:
        full_prompt = (system + "\n\n" + prompt) if system else prompt
        resp = self.model.generate_content(
            full_prompt,
            generation_config={"response_mime_type": "application/json"},
        )
        return getattr(resp, "text", "") or ""

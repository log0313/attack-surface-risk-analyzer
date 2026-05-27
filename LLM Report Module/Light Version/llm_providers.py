"""LLM Providers - Google AI Studio Native Integration."""
import os
import json
from google import genai
from google.genai import types


class GeminiProvider:
    def __init__(self):
        # 환경변수에서 GEMINI_API_KEY를 읽어옵니다.
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("[!] 환경변수에 'GEMINI_API_KEY'가 설정되어 있지 않습니다.")

        self.client = genai.Client(api_key=api_key)
        self.model_name = "gemini-3.5-flash"

    def generate(self, prompt: str, system: str) -> str:
        """구글 Gemini API를 직접 호출하여 응답을 획득합니다."""
        try:
            response = self.client.models.generate_content(
                model="gemini-3.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    temperature=0.2,
                    max_output_tokens=8192,
                    response_mime_type="application/json",
                    safety_settings=[
                        types.SafetySetting(
                            category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                            threshold=types.HarmBlockThreshold.BLOCK_NONE,
                        ),
                        types.SafetySetting(
                            category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                            threshold=types.HarmBlockThreshold.BLOCK_NONE,
                        ),
                        types.SafetySetting(
                            category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                            threshold=types.HarmBlockThreshold.BLOCK_NONE,
                        ),
                        types.SafetySetting(
                            category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                            threshold=types.HarmBlockThreshold.BLOCK_NONE,
                        ),
                    ]
                )
            )
            return response.text
        except Exception as e:
            raise RuntimeError(f"Gemini API 호출 중 장애가 발생했습니다: {e}")


def get_provider(name: str = "gemini"):
    return GeminiProvider()

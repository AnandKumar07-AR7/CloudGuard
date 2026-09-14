"""
CloudGuard Gemini Client
Google Gemini API integration for security analysis.
"""

import json
from typing import Optional
from app.config import settings


class GeminiClient:
    """Google Gemini API client for AI-powered security analysis."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        """Lazy-initialize the Gemini client."""
        if self._client is None:
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY is not configured")
            from google import genai
            self._client = genai.Client(api_key=settings.gemini_api_key)
        return self._client

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "gemini-2.0-flash",
    ) -> Optional[dict]:
        """
        Send a prompt to Gemini and return the parsed JSON response.

        Args:
            system_prompt: System context for the AI
            user_prompt: The specific analysis request
            model: Gemini model to use

        Returns:
            Parsed JSON dict from the AI response, or None on failure
        """
        try:
            client = self._get_client()

            response = client.models.generate_content(
                model=model,
                contents=user_prompt,
                config={
                    "system_instruction": system_prompt,
                    "temperature": 0.2,  # Low temperature for consistent analysis
                    "response_mime_type": "application/json",
                },
            )

            if response and response.text:
                return self._parse_json_response(response.text)
            return None

        except Exception as e:
            print(f"[GeminiClient] Error: {str(e)}")
            return None

    def _parse_json_response(self, text: str) -> Optional[dict]:
        """Parse JSON from the model response, handling common formatting issues."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in text:
                json_str = text.split("```json")[1].split("```")[0].strip()
                return json.loads(json_str)
            elif "```" in text:
                json_str = text.split("```")[1].split("```")[0].strip()
                return json.loads(json_str)
            print(f"[GeminiClient] Failed to parse JSON response: {text[:200]}")
            return None

    @property
    def is_available(self) -> bool:
        """Check if the Gemini client can be used."""
        return settings.is_gemini_configured


gemini_client = GeminiClient()

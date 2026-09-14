"""
CloudGuard Claude Client
Anthropic Claude API integration for deep security analysis.
"""

import json
from typing import Optional
from app.config import settings


class ClaudeClient:
    """Anthropic Claude API client for deep AI security analysis."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        """Lazy-initialize the Claude client."""
        if self._client is None:
            if not settings.anthropic_api_key:
                raise ValueError("ANTHROPIC_API_KEY is not configured")
            import anthropic
            self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        return self._client

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "claude-sonnet-4-20250514",
    ) -> Optional[dict]:
        """
        Send a prompt to Claude and return the parsed JSON response.

        Args:
            system_prompt: System context for the AI
            user_prompt: The specific analysis request
            model: Claude model to use

        Returns:
            Parsed JSON dict from the AI response, or None on failure
        """
        try:
            client = self._get_client()

            message = client.messages.create(
                model=model,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
            )

            if message and message.content:
                text = message.content[0].text
                return self._parse_json_response(text)
            return None

        except Exception as e:
            print(f"[ClaudeClient] Error: {str(e)}")
            return None

    def _parse_json_response(self, text: str) -> Optional[dict]:
        """Parse JSON from the model response."""
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
            print(f"[ClaudeClient] Failed to parse JSON response: {text[:200]}")
            return None

    @property
    def is_available(self) -> bool:
        """Check if the Claude client can be used."""
        return settings.is_claude_configured


claude_client = ClaudeClient()

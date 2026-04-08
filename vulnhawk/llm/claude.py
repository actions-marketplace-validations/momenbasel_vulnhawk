"""Anthropic Claude backend."""

from __future__ import annotations

import os

from vulnhawk.llm.base import BaseLLM, LLMResponse


class ClaudeLLM(BaseLLM):
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.model = model
        self._api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        response = await client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        return LLMResponse(
            content=response.content[0].text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=self.model,
        )

"""OpenAI backend."""

from __future__ import annotations

import os

from vulnhawk.llm.base import BaseLLM, LLMResponse


class OpenAILLM(BaseLLM):
    name = "openai"

    def __init__(self, model: str = "gpt-4o"):
        self.model = model
        self._api_key = os.environ.get("OPENAI_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self._api_key)
        response = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=4096,
        )

        usage = response.usage
        return LLMResponse(
            content=response.choices[0].message.content or "",
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=self.model,
        )

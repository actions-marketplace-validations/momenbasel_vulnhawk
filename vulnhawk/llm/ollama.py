"""Ollama local LLM backend."""

from __future__ import annotations

import httpx

from vulnhawk.llm.base import BaseLLM, LLMResponse


class OllamaLLM(BaseLLM):
    name = "ollama"

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def is_configured(self) -> bool:
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            model=self.model,
        )

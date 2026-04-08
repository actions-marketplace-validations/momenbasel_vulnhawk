"""Abstract base for LLM backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Parsed response from an LLM."""

    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""


class BaseLLM(ABC):
    """Abstract LLM backend."""

    name: str = "base"

    @abstractmethod
    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Send a prompt and return the response."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the backend has valid credentials."""
        ...

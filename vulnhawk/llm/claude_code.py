"""Claude Code CLI backend - FREE for Claude Code subscribers.

Uses the `claude` CLI tool with --print flag to analyze code.
Authenticates via the user's existing Claude Code subscription,
so no separate API key or per-token billing is needed.
"""

from __future__ import annotations

import asyncio
import os
import shutil

from vulnhawk.llm.base import BaseLLM, LLMResponse


class ClaudeCodeLLM(BaseLLM):
    name = "claude-code"

    def __init__(self, model: str = "sonnet"):
        self.model = model
        self._oauth_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")

    def is_configured(self) -> bool:
        # Check 1: claude CLI must be installed
        if not shutil.which("claude"):
            return False
        # Check 2: either CLAUDE_CODE_OAUTH_TOKEN is set (CI) or
        # the user is already logged in locally (interactive)
        if self._oauth_token:
            return True
        # If no token env var, check if claude CLI is authenticated
        # by running a quick version check (doesn't need auth)
        # In local dev, the CLI uses ~/.claude/ credentials automatically
        return True

    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"

        env = os.environ.copy()
        if self._oauth_token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = self._oauth_token

        cmd = [
            "claude",
            "--print",
            "--model", self.model,
            "--max-turns", "1",
            "--output-format", "text",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await proc.communicate(input=combined_prompt.encode())

        if proc.returncode != 0:
            error_msg = stderr.decode().strip()
            raise RuntimeError(f"Claude Code CLI failed (exit {proc.returncode}): {error_msg}")

        content = stdout.decode().strip()

        # Claude Code CLI doesn't expose token counts, estimate from char length
        estimated_input = len(combined_prompt) // 4
        estimated_output = len(content) // 4

        return LLMResponse(
            content=content,
            input_tokens=estimated_input,
            output_tokens=estimated_output,
            model=f"claude-code/{self.model}",
        )

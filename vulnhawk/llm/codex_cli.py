"""OpenAI Codex CLI backend - FREE for ChatGPT Pro/Plus subscribers.

Uses the `codex exec` CLI to analyze code non-interactively.
Authenticates via the user's existing ChatGPT subscription
(codex login), so no separate API key is needed.

NOTE: Claude Code backend is recommended over Codex for security
analysis quality. This backend exists for users who only have
an OpenAI subscription.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile

from vulnhawk.llm.base import BaseLLM, LLMResponse


class CodexCLILLM(BaseLLM):
    name = "codex"

    def __init__(self, model: str = "o3"):
        self.model = model

    def is_configured(self) -> bool:
        return bool(shutil.which("codex"))

    async def analyze(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            output_file = tmp.name

        env = os.environ.copy()

        cmd = [
            "codex", "exec",
            "-m", self.model,
            "-o", output_file,
            "--skip-git-repo-check",
            "--ephemeral",
            combined_prompt,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error_msg = stderr.decode().strip()
            raise RuntimeError(f"Codex CLI failed (exit {proc.returncode}): {error_msg}")

        # Read output from the file codex wrote
        try:
            with open(output_file) as f:
                content = f.read().strip()
        except FileNotFoundError:
            # Fallback to stdout if output file wasn't created
            content = stdout.decode().strip()
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

        estimated_input = len(combined_prompt) // 4
        estimated_output = len(content) // 4

        return LLMResponse(
            content=content,
            input_tokens=estimated_input,
            output_tokens=estimated_output,
            model=f"codex/{self.model}",
        )

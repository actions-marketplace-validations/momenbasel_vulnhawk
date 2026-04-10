"""Core scanning engine - orchestrates chunking, analysis, and result aggregation."""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from vulnhawk.llm.base import BaseLLM
from vulnhawk.models import CodeChunk, Finding, ScanMode, ScanResult, Severity
from vulnhawk.rules.prompts import SCAN_MODE_ADDITIONS, SYSTEM_PROMPT, build_analysis_prompt
from vulnhawk.scanner.chunker import chunk_codebase, chunk_file

# Max concurrent LLM requests
MAX_CONCURRENCY = 5


def _find_related_chunks(chunk: CodeChunk, all_chunks: list[CodeChunk]) -> list[str]:
    """Find related code patterns for context enrichment.

    This is the SECRET SAUCE: by showing the LLM how OTHER parts of the codebase
    handle auth, validation, etc., it can spot inconsistencies.
    """
    related = []

    # Find chunks in the same directory or with similar names
    same_dir = [
        c for c in all_chunks
        if c.file_path.parent == chunk.file_path.parent
        and c.file_path != chunk.file_path
        and c.chunk_type in ("function", "route")
    ]

    # Find chunks that look like auth/middleware patterns
    auth_keywords = ["auth", "login", "verify", "check", "guard", "middleware", "protect", "permission"]
    auth_patterns = [
        c for c in all_chunks
        if any(kw in c.name.lower() for kw in auth_keywords)
        and c.file_path != chunk.file_path
    ]

    # Prioritize: same-directory routes/handlers, then auth patterns
    candidates = same_dir[:3] + auth_patterns[:2]

    for c in candidates:
        # Truncate to keep context manageable
        snippet = c.content[:500]
        if len(c.content) > 500:
            snippet += "\n... (truncated)"
        related.append(f"# {c.file_path}:{c.start_line} - {c.chunk_type} {c.name}\n{snippet}")

    return related


def _parse_findings(raw: str, chunk: CodeChunk) -> list[Finding]:
    """Parse LLM response into Finding objects."""
    # Extract JSON array from response
    raw = raw.strip()

    # Try to find JSON array in the response
    json_match = re.search(r"\[[\s\S]*\]", raw)
    if not json_match:
        return []

    try:
        data = json.loads(json_match.group())
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        try:
            severity_str = item.get("severity", "info").lower()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.INFO

            finding = Finding(
                title=item.get("title", "Untitled finding"),
                severity=severity,
                description=item.get("description", ""),
                file_path=item.get("file_path", str(chunk.file_path)),
                start_line=item.get("start_line", chunk.start_line),
                end_line=item.get("end_line", chunk.end_line),
                code_snippet=item.get("code_snippet", ""),
                fix_suggestion=item.get("fix_suggestion", ""),
                confidence=float(item.get("confidence", 0.5)),
                cwe_id=item.get("cwe_id", ""),
                category=item.get("category", ""),
            )
            findings.append(finding)
        except (ValueError, TypeError, KeyError):
            continue

    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on fingerprint."""
    seen: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint
        if fp not in seen or f.confidence > seen[fp].confidence:
            seen[fp] = f
    return list(seen.values())


async def _analyze_chunk(
    chunk: CodeChunk,
    llm: BaseLLM,
    system_prompt: str,
    all_chunks: list[CodeChunk],
    semaphore: asyncio.Semaphore,
) -> list[Finding]:
    """Analyze a single code chunk."""
    # Skip test files unless scanning for secrets
    if chunk.is_test:
        return []

    # Skip very small chunks (likely just imports or constants)
    if chunk.content.strip().count("\n") < 3:
        return []

    related = _find_related_chunks(chunk, all_chunks)

    context = {
        "file_path": str(chunk.file_path),
        "language": chunk.language.value,
        "chunk_type": chunk.chunk_type,
        "name": chunk.name,
        "start_line": chunk.start_line,
        "end_line": chunk.end_line,
        "is_test": chunk.is_test,
        "imports": chunk.imports,
        "related_code": related,
    }

    user_prompt = build_analysis_prompt(chunk.content, context)

    async with semaphore:
        try:
            response = await llm.analyze(system_prompt, user_prompt)
            return _parse_findings(response.content, chunk)
        except Exception:
            return []


async def scan(
    target: Path,
    llm: BaseLLM,
    mode: ScanMode = ScanMode.FULL,
    min_severity: Severity = Severity.LOW,
    show_progress: bool = True,
    sarif_context: str = "",
) -> ScanResult:
    """Run a security scan on a target path."""
    start_time = time.time()

    # Build system prompt
    system = SYSTEM_PROMPT
    if mode != ScanMode.FULL and mode.value in SCAN_MODE_ADDITIONS:
        system += SCAN_MODE_ADDITIONS[mode.value]

    # Append SARIF context from other tools if provided
    if sarif_context:
        system += f"\n\n{sarif_context}"

    # Chunk the codebase
    if target.is_file():
        chunks = chunk_file(target)
        scanned_files = [target]
    else:
        chunks, scanned_files = chunk_codebase(target)

    if not chunks:
        return ScanResult(
            target=str(target),
            files_scanned=0,
            chunks_analyzed=0,
            scan_duration=time.time() - start_time,
            llm_backend=llm.name,
        )

    # Analyze chunks concurrently
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    all_findings: list[Finding] = []

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[dim]{task.completed}/{task.total} chunks"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Analyzing", total=len(chunks))

            async def analyze_with_progress(chunk: CodeChunk) -> list[Finding]:
                result = await _analyze_chunk(chunk, llm, system, chunks, semaphore)
                progress.advance(task)
                return result

            tasks = [analyze_with_progress(chunk) for chunk in chunks]
            results = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        tasks = [_analyze_chunk(chunk, llm, system, chunks, semaphore) for chunk in chunks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)

    # Post-process
    all_findings = _deduplicate(all_findings)

    # Filter by minimum severity
    all_findings = [f for f in all_findings if f.severity.rank >= min_severity.rank]

    # Sort by severity (highest first), then confidence
    all_findings.sort(key=lambda f: (f.severity.rank, f.confidence), reverse=True)

    return ScanResult(
        target=str(target),
        findings=all_findings,
        files_scanned=len(scanned_files),
        chunks_analyzed=len(chunks),
        scan_duration=time.time() - start_time,
        llm_backend=llm.name,
    )

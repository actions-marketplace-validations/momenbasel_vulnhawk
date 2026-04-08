"""Markdown report output."""

from __future__ import annotations

from vulnhawk.models import ScanResult, Severity


def render(result: ScanResult) -> str:
    """Render scan results as a Markdown report."""
    lines = []

    lines.append("# VulnHawk Security Scan Report\n")
    lines.append(f"**Target:** `{result.target}`\n")
    lines.append(
        f"**Backend:** {result.llm_backend} | **Files:** {result.files_scanned}"
        f" | **Duration:** {result.scan_duration:.1f}s\n"
    )

    # Summary
    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")

    severity_counts: dict[Severity, int] = {}
    for finding in result.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "-", "info": "i"}
            lines.append(f"| {icon.get(sev.value, '')} **{sev.value.upper()}** | {count} |")

    lines.append(f"\n**Total:** {len(result.findings)} findings\n")

    if not result.findings:
        lines.append("\nNo vulnerabilities found.\n")
        return "\n".join(lines)

    # Findings
    lines.append("## Findings\n")

    for i, finding in enumerate(result.findings, 1):
        lines.append(f"### {i}. [{finding.severity.value.upper()}] {finding.title}\n")

        if finding.cwe_id:
            lines.append(f"**CWE:** {finding.cwe_id} | ", )
        lines.append(f"**Confidence:** {finding.confidence:.0%} | **Category:** {finding.category}\n")
        lines.append(f"**Location:** `{finding.file_path}:{finding.start_line}-{finding.end_line}`\n")

        lines.append(f"**Description:**\n{finding.description}\n")

        if finding.code_snippet:
            lines.append(f"**Vulnerable Code:**\n```\n{finding.code_snippet}\n```\n")

        if finding.fix_suggestion:
            lines.append(f"**Remediation:**\n{finding.fix_suggestion}\n")

        lines.append("---\n")

    return "\n".join(lines)

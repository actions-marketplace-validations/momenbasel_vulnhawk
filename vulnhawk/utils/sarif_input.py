"""Parse SARIF input from other SAST tools to enrich VulnHawk analysis."""

from __future__ import annotations

import json
from pathlib import Path


def parse_sarif_input(sarif_path: str | Path) -> list[dict]:
    """Parse a SARIF file and extract findings as context for VulnHawk.

    Returns a list of dicts with keys:
    - tool: str (e.g. "Semgrep", "CodeQL")
    - rule_id: str
    - message: str
    - file_path: str
    - start_line: int
    - severity: str
    """
    sarif_path = Path(sarif_path)
    if not sarif_path.exists():
        return []

    with open(sarif_path) as f:
        data = json.load(f)

    findings = []

    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

        # Build rule index for severity lookup
        rule_map = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            level = rule.get("defaultConfiguration", {}).get("level", "warning")
            rule_map[rule.get("id", "")] = level

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", rule_map.get(rule_id, "warning"))

            # Map SARIF levels to severity strings
            severity_map = {
                "error": "high",
                "warning": "medium",
                "note": "low",
                "none": "info",
            }
            severity = severity_map.get(level, "medium")

            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})

                findings.append({
                    "tool": tool_name,
                    "rule_id": rule_id,
                    "message": message,
                    "file_path": artifact.get("uri", ""),
                    "start_line": region.get("startLine", 0),
                    "severity": severity,
                })

    return findings


def format_sarif_context(findings: list[dict]) -> str:
    """Format parsed SARIF findings as context for the LLM prompt."""
    if not findings:
        return ""

    lines = ["## Prior SAST Findings (from other tools - use as additional context)"]
    lines.append("The following findings were reported by other SAST tools. Use them to:")
    lines.append("1. Validate and expand on these findings with deeper analysis")
    lines.append("2. Look for related vulnerabilities near these locations")
    lines.append("3. Check if the suggested fixes actually address the root cause")
    lines.append("4. Find multi-step attack chains that connect these findings")
    lines.append("")

    # Group by file
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file_path"], []).append(f)

    for file_path, file_findings in by_file.items():
        lines.append(f"### {file_path}")
        for f in file_findings:
            lines.append(f"- [{f['severity'].upper()}] {f['tool']}/{f['rule_id']} (line {f['start_line']}): {f['message']}")
        lines.append("")

    return "\n".join(lines)

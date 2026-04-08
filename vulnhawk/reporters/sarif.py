"""SARIF output for GitHub Code Scanning integration."""

from __future__ import annotations

import json

from vulnhawk import __version__
from vulnhawk.models import ScanResult, Severity

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render(result: ScanResult) -> str:
    """Render scan results as SARIF JSON."""
    rules = []
    results = []
    rule_ids: dict[str, int] = {}

    for finding in result.findings:
        # Create or reuse rule
        rule_id = finding.cwe_id or f"VULNHAWK-{finding.category or 'generic'}"
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description[:1000]},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                },
                "properties": {
                    "security-severity": _cvss_estimate(finding.severity),
                },
            })

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.description}\n\nFix: {finding.fix_suggestion}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": finding.start_line,
                            "endLine": finding.end_line,
                        },
                    },
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "category": finding.category,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnHawk",
                        "version": __version__,
                        "informationUri": "https://github.com/momenbasel/vulnhawk",
                        "rules": rules,
                    },
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def _cvss_estimate(severity: Severity) -> str:
    """Rough CVSS score estimate for SARIF security-severity."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.5",
        Severity.INFO: "0.0",
    }.get(severity, "5.0")

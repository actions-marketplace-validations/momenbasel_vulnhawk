"""Tests for output reporters."""

import json

from vulnhawk.models import Finding, ScanResult, Severity
from vulnhawk.reporters import json_reporter, markdown, sarif


def _sample_result() -> ScanResult:
    return ScanResult(
        target="/tmp/test-project",
        findings=[
            Finding(
                title="SQL Injection in search_users",
                severity=Severity.CRITICAL,
                description="User input directly concatenated into SQL query.",
                file_path="app/routes.py",
                start_line=42,
                end_line=45,
                code_snippet='db.execute(f"SELECT * FROM users WHERE name LIKE \'%{query}%\'")',
                fix_suggestion=(
                    "Use parameterized queries: "
                    "db.execute('SELECT * FROM users WHERE name LIKE ?', (f'%{query}%',))"
                ),
                confidence=0.95,
                cwe_id="CWE-89",
                category="injection",
            ),
            Finding(
                title="Hardcoded API Key",
                severity=Severity.HIGH,
                description="AWS access key hardcoded in source code.",
                file_path="config.py",
                start_line=10,
                end_line=10,
                code_snippet='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
                fix_suggestion="Use environment variables or a secrets manager.",
                confidence=0.90,
                cwe_id="CWE-798",
                category="secrets",
            ),
        ],
        files_scanned=15,
        chunks_analyzed=42,
        scan_duration=12.5,
        llm_backend="claude",
    )


def test_json_reporter():
    result = _sample_result()
    output = json_reporter.render(result)
    data = json.loads(output)

    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["cwe_id"] == "CWE-89"


def test_sarif_reporter():
    result = _sample_result()
    output = sarif.render(result)
    data = json.loads(output)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "VulnHawk"
    assert len(data["runs"][0]["results"]) == 2


def test_markdown_reporter():
    result = _sample_result()
    output = markdown.render(result)

    assert "# VulnHawk Security Scan Report" in output
    assert "SQL Injection" in output
    assert "CWE-89" in output
    assert "CRITICAL" in output


def test_empty_result():
    result = ScanResult(
        target="/tmp/empty",
        files_scanned=5,
        chunks_analyzed=10,
        scan_duration=2.0,
        llm_backend="claude",
    )

    json_output = json.loads(json_reporter.render(result))
    assert json_output["summary"]["total_findings"] == 0

    md_output = markdown.render(result)
    assert "No vulnerabilities found" in md_output

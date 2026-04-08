"""Tests for data models."""

from vulnhawk.models import Finding, ScanResult, Severity


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank
    assert Severity.LOW.rank > Severity.INFO.rank


def test_finding_fingerprint():
    f1 = Finding(
        title="SQL Injection",
        severity=Severity.CRITICAL,
        description="test",
        file_path="app.py",
        start_line=10,
        end_line=15,
        code_snippet="",
        fix_suggestion="",
        confidence=0.9,
        cwe_id="CWE-89",
    )
    f2 = Finding(
        title="SQL Injection",
        severity=Severity.CRITICAL,
        description="different desc",
        file_path="app.py",
        start_line=10,
        end_line=15,
        code_snippet="",
        fix_suggestion="",
        confidence=0.8,
        cwe_id="CWE-89",
    )
    # Same fingerprint for dedup
    assert f1.fingerprint == f2.fingerprint


def test_scan_result_counts():
    result = ScanResult(target="/test")
    result.findings = [
        Finding(
            title="a", severity=Severity.CRITICAL, description="", file_path="",
            start_line=1, end_line=1, code_snippet="", fix_suggestion="",
            confidence=0.9,
        ),
        Finding(
            title="b", severity=Severity.HIGH, description="", file_path="",
            start_line=1, end_line=1, code_snippet="", fix_suggestion="",
            confidence=0.9,
        ),
        Finding(
            title="c", severity=Severity.HIGH, description="", file_path="",
            start_line=1, end_line=1, code_snippet="", fix_suggestion="",
            confidence=0.9,
        ),
    ]
    assert result.critical_count == 1
    assert result.high_count == 2


def test_severity_by_groups():
    result = ScanResult(target="/test")
    result.findings = [
        Finding(
            title="a", severity=Severity.CRITICAL, description="", file_path="",
            start_line=1, end_line=1, code_snippet="", fix_suggestion="",
            confidence=0.9,
        ),
        Finding(
            title="b", severity=Severity.LOW, description="", file_path="",
            start_line=1, end_line=1, code_snippet="", fix_suggestion="",
            confidence=0.9,
        ),
    ]
    grouped = result.findings_by_severity
    assert Severity.CRITICAL in grouped
    assert Severity.LOW in grouped
    assert len(grouped[Severity.CRITICAL]) == 1

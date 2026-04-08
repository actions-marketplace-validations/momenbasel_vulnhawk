"""JSON output reporter."""

from __future__ import annotations

import json

from vulnhawk.models import ScanResult


def render(result: ScanResult) -> str:
    """Render scan results as JSON string."""
    data = {
        "target": result.target,
        "summary": {
            "files_scanned": result.files_scanned,
            "chunks_analyzed": result.chunks_analyzed,
            "scan_duration": round(result.scan_duration, 2),
            "llm_backend": result.llm_backend,
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
        },
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "code_snippet": f.code_snippet,
                "fix_suggestion": f.fix_suggestion,
                "confidence": f.confidence,
                "cwe_id": f.cwe_id,
                "category": f.category,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }

    return json.dumps(data, indent=2)

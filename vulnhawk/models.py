"""Core data models for VulnHawk."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "[!]",
            Severity.HIGH: "[!]",
            Severity.MEDIUM: "[*]",
            Severity.LOW: "[-]",
            Severity.INFO: "[i]",
        }[self]

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class ScanMode(str, Enum):
    FULL = "full"
    AUTH = "auth"
    INJECTION = "injection"
    SECRETS = "secrets"
    CONFIG = "config"
    CRYPTO = "crypto"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    UNKNOWN = "unknown"

    @classmethod
    def from_extension(cls, ext: str) -> Language:
        mapping = {
            ".py": cls.PYTHON,
            ".js": cls.JAVASCRIPT,
            ".jsx": cls.JAVASCRIPT,
            ".ts": cls.TYPESCRIPT,
            ".tsx": cls.TYPESCRIPT,
            ".go": cls.GO,
            ".java": cls.JAVA,
        }
        return mapping.get(ext.lower(), cls.UNKNOWN)


@dataclass
class CodeChunk:
    """A logical chunk of code for analysis."""

    file_path: Path
    language: Language
    content: str
    start_line: int
    end_line: int
    chunk_type: str  # function, class, route, module
    name: str  # function/class name or file name
    imports: list[str] = field(default_factory=list)
    related_code: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def is_test(self) -> bool:
        path_str = str(self.file_path).lower()
        return any(
            marker in path_str
            for marker in ["test_", "_test.", "tests/", "test/", "__tests__", ".spec.", ".test."]
        )


@dataclass
class Finding:
    """A security finding from analysis."""

    title: str
    severity: Severity
    description: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    fix_suggestion: str
    confidence: float  # 0.0 - 1.0
    cwe_id: str = ""
    category: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        return f"{self.cwe_id}:{self.file_path}:{self.start_line}:{self.title[:50]}"


@dataclass
class ScanResult:
    """Complete scan result."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    chunks_analyzed: int = 0
    scan_duration: float = 0.0
    llm_backend: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for finding in sorted(self.findings, key=lambda f: f.severity.rank, reverse=True):
            result.setdefault(finding.severity, []).append(finding)
        return result

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

"""Tests for the code chunker."""

from pathlib import Path

from vulnhawk.models import Language
from vulnhawk.scanner.chunker import chunk_file, extract_imports, load_ignore_spec

FIXTURES = Path(__file__).parent / "fixtures"


def test_chunk_python_file():
    chunks = chunk_file(FIXTURES / "vulnerable_python.py")
    assert len(chunks) > 0
    # Should find functions like get_user_profile, search_users, etc.
    names = [c.name for c in chunks]
    assert "get_user_profile" in names
    assert "search_users" in names
    assert "hash_password" in names


def test_chunk_js_file():
    chunks = chunk_file(FIXTURES / "vulnerable_js.js")
    assert len(chunks) > 0
    # Should detect route handlers
    route_chunks = [c for c in chunks if c.chunk_type == "route"]
    assert len(route_chunks) > 0


def test_chunk_go_file():
    chunks = chunk_file(FIXTURES / "vulnerable_go.go")
    assert len(chunks) > 0
    names = [c.name for c in chunks]
    assert "searchUsers" in names
    assert "pingHost" in names


def test_python_imports():
    content = "import os\nfrom pathlib import Path\nimport json\n"
    imports = extract_imports(content, Language.PYTHON)
    assert len(imports) == 3
    assert "import os" in imports


def test_js_imports():
    content = """const express = require('express');\nimport foo from 'bar';\n"""
    imports = extract_imports(content, Language.JAVASCRIPT)
    assert len(imports) >= 1


def test_language_detection():
    assert Language.from_extension(".py") == Language.PYTHON
    assert Language.from_extension(".js") == Language.JAVASCRIPT
    assert Language.from_extension(".ts") == Language.TYPESCRIPT
    assert Language.from_extension(".go") == Language.GO
    assert Language.from_extension(".xyz") == Language.UNKNOWN


def test_ignore_spec():
    spec = load_ignore_spec(FIXTURES)
    assert spec.match_file("node_modules/foo.js")
    assert spec.match_file("__pycache__/bar.pyc")
    assert not spec.match_file("src/app.py")


def test_is_test_detection():
    # Fixtures are inside tests/ directory, so is_test is True
    chunks = chunk_file(FIXTURES / "vulnerable_python.py")
    for chunk in chunks:
        assert chunk.is_test  # in tests/fixtures/ directory

    # Simulate a non-test file path
    from vulnhawk.models import CodeChunk
    prod_chunk = CodeChunk(
        file_path=Path("src/routes/auth.py"),
        language=Language.PYTHON,
        content="def login(): pass",
        start_line=1,
        end_line=1,
        chunk_type="function",
        name="login",
    )
    assert not prod_chunk.is_test

    # Simulate a test file path
    test_chunk = CodeChunk(
        file_path=Path("tests/test_auth.py"),
        language=Language.PYTHON,
        content="def test_login(): pass",
        start_line=1,
        end_line=1,
        chunk_type="function",
        name="test_login",
    )
    assert test_chunk.is_test

# Contributing to VulnHawk

Thanks for your interest in contributing.

## Development Setup

```bash
git clone https://github.com/momenbasel/vulnhawk.git
cd vulnhawk
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Code Style

We use `ruff` for linting:

```bash
ruff check .
ruff format .
```

## Adding Language Support

1. Create a new file in `vulnhawk/scanner/languages/`
2. Add the extension mapping in `vulnhawk/models.py` (`Language.from_extension`)
3. Add the splitter function in `vulnhawk/scanner/chunker.py`
4. Add test fixtures in `tests/fixtures/`
5. Add tests in `tests/test_chunker.py`

## Adding a New LLM Backend

1. Create a new file in `vulnhawk/llm/`
2. Implement the `BaseLLM` interface
3. Add the backend choice in `vulnhawk/cli.py`
4. Document any required environment variables

## Reporting Security Issues

If you find a security vulnerability in VulnHawk itself, please report it privately via GitHub Security Advisories rather than opening a public issue.

## Pull Requests

- Keep PRs focused on a single change
- Add tests for new functionality
- Update documentation if needed
- Run `ruff check .` before submitting

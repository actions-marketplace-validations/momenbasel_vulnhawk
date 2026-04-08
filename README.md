<p align="center">
  <a href="https://pypi.org/project/vulnhawk/"><img alt="PyPI" src="https://img.shields.io/pypi/v/vulnhawk.svg?style=flat&label=PyPI&color=blue"></a>
  <a href="https://pypi.org/project/vulnhawk/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/vulnhawk.svg?style=flat"></a>
  <a href="https://github.com/marketplace/actions/vulnhawk-security-scan"><img alt="GitHub Marketplace" src="https://img.shields.io/badge/Marketplace-VulnHawk-2088FF?style=flat&logo=github-actions&logoColor=white"></a>
  <a href="https://github.com/momenbasel/vulnhawk/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/momenbasel/vulnhawk.svg?style=flat"></a>
  <a href="https://github.com/momenbasel/vulnhawk/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/momenbasel/vulnhawk.svg?style=social"></a>
  <a href="https://pypi.org/project/vulnhawk/"><img alt="Downloads" src="https://img.shields.io/pypi/dm/vulnhawk.svg?style=flat&label=downloads"></a>
</p>

<h1 align="center">VulnHawk</h1>

<p align="center">
  <strong>AI-powered code security scanner that finds vulnerabilities<br>Semgrep and CodeQL miss.</strong>
</p>

<p align="center">
  VulnHawk uses AI to understand your code's <em>business logic</em> - not just pattern matching.<br>
  It spots missing auth checks, IDOR flaws, and logic bugs that rule-based tools can't detect.
</p>

---

## Installation

**CLI via PyPI:**
```bash
pip install vulnhawk
```

**GitHub Action via Marketplace:**
```yaml
- uses: momenbasel/vulnhawk@v0.1.0
  with:
    target: '.'
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

<p align="center">
  <img src="docs/demo.svg" alt="VulnHawk Demo" width="800">
</p>

---

## What Makes VulnHawk Different

Traditional scanners (Semgrep, CodeQL, Bandit) use pattern matching and AST rules. They're great at finding known patterns, but they **can't understand intent**.

VulnHawk analyzes your code with AI and cross-references how different parts of your codebase handle security. If 12 endpoints check authorization but one doesn't, VulnHawk catches it.

| Feature | Semgrep / CodeQL | VulnHawk |
|---------|-----------------|----------|
| Detection method | AST pattern matching | AI code understanding |
| Business logic bugs | Cannot detect | Detects missing auth, IDOR, logic flaws |
| Cross-file analysis | Requires custom rules | Automatic - compares similar code patterns |
| Setup | Write rules, configure | Zero config - works immediately |
| Finding descriptions | Rule IDs and templates | Natural language with attack scenarios |
| Fix suggestions | Generic recommendations | Context-specific code fixes |

## Quick Start

```bash
pip install vulnhawk
```

Set your LLM API key:
```bash
export ANTHROPIC_API_KEY=sk-ant-...    # Claude (default)
# or
export OPENAI_API_KEY=sk-...           # OpenAI
# or just run Ollama locally           # Free, no API key needed
```

Scan your code:
```bash
vulnhawk scan ./src
```

That's it. No config files, no rule writing, no setup.

## Usage

### Basic scan
```bash
vulnhawk scan ./src
```

### Focused scanning
```bash
# Only check authentication and authorization
vulnhawk scan ./src --mode auth

# Only check for injection vulnerabilities
vulnhawk scan ./api --mode injection

# Only look for hardcoded secrets
vulnhawk scan . --mode secrets
```

### Output formats
```bash
# JSON output
vulnhawk scan ./src -o json -f results.json

# SARIF for GitHub Code Scanning
vulnhawk scan ./src -o sarif -f results.sarif

# Markdown report
vulnhawk scan ./src -o markdown -f report.md
```

### Different LLM backends
```bash
# Claude (default, best results)
vulnhawk scan ./src -b claude

# OpenAI
vulnhawk scan ./src -b openai -m gpt-4o

# Ollama (free, local, private)
vulnhawk scan ./src -b ollama -m llama3.1
```

### Filter by severity
```bash
# Only critical and high
vulnhawk scan ./src --severity high

# Everything including info
vulnhawk scan ./src --severity info
```

### Preview what will be scanned
```bash
vulnhawk info ./src
```

## GitHub Action

Add VulnHawk to your CI/CD pipeline:

```yaml
name: Security Scan
on: [pull_request]

permissions:
  security-events: write

jobs:
  vulnhawk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: momenbasel/vulnhawk@main
        with:
          target: '.'
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          severity: 'medium'
          fail-on-findings: 'true'
```

Results automatically appear in GitHub's **Security** tab via SARIF upload.

## Scan Modes

| Mode | What it checks |
|------|---------------|
| `full` | Everything (default) |
| `auth` | Authentication bypass, missing auth checks, session flaws, JWT issues |
| `injection` | SQLi, command injection, SSTI, NoSQL injection, XSS |
| `secrets` | Hardcoded API keys, passwords, tokens, connection strings |
| `config` | Debug mode, verbose errors, permissive CORS, insecure cookies |
| `crypto` | Weak hashing, hardcoded keys, insecure random, deprecated algorithms |

## Supported Languages

- Python
- JavaScript / TypeScript
- Go
- More coming soon (Java, Ruby, PHP, Rust)

## How It Works

1. **Discover** - Walks your codebase, respects `.gitignore` and `.vulnhawkignore`
2. **Chunk** - Splits code into logical pieces (functions, classes, routes) with surrounding context
3. **Enrich** - For each chunk, includes import context and **related code** from elsewhere in the codebase (this is the key differentiator - it shows the AI how other parts handle auth, validation, etc.)
4. **Analyze** - Sends enriched chunks to the LLM with security-focused analysis prompts
5. **Validate** - Cross-references findings, removes duplicates, assigns confidence scores
6. **Report** - Formats results with code snippets, attack scenarios, and fix suggestions

The **enrichment step** is what makes VulnHawk fundamentally different. By showing the AI how similar endpoints in your codebase handle security, it can spot the one that doesn't.

## Configuration

### .vulnhawkignore

Create a `.vulnhawkignore` file to exclude paths (same syntax as `.gitignore`):

```
# Skip generated code
generated/
*.gen.go

# Skip vendor dependencies
vendor/
third_party/
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude backend |
| `OPENAI_API_KEY` | API key for OpenAI backend |

## FAQ

**How much does it cost to run?**
Depends on codebase size and LLM backend. A typical scan of a medium project (~100 files) costs about $0.50-$2.00 with Claude. Use Ollama for free local scanning.

**Will it find everything?**
No security tool catches everything. VulnHawk is best at finding business logic bugs, missing authorization, and context-dependent vulnerabilities that pattern-matching tools miss. Use it alongside (not instead of) Semgrep/CodeQL.

**Is my code sent to an external API?**
Yes, code chunks are sent to the configured LLM provider (Anthropic, OpenAI). Use the Ollama backend for fully local, private scanning.

**Does it support monorepos?**
Yes. Point it at any directory and it will scan all supported files recursively.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/momenbasel/vulnhawk.git
cd vulnhawk
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest
```

## License

MIT - see [LICENSE](LICENSE)

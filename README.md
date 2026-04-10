<p align="center">
  <a href="https://pypi.org/project/vulnhawk/"><img alt="PyPI" src="https://img.shields.io/pypi/v/vulnhawk.svg?style=flat&label=PyPI&color=blue"></a>
  <a href="https://pypi.org/project/vulnhawk/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/vulnhawk.svg?style=flat"></a>
  <a href="https://github.com/marketplace/actions/vulnhawk-security-scan"><img alt="GitHub Marketplace" src="https://img.shields.io/badge/Marketplace-VulnHawk-2088FF?style=flat&logo=github-actions&logoColor=white"></a>
  <a href="https://github.com/momenbasel/vulnhawk/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Source%20Available-orange.svg?style=flat"></a>
  <a href="https://github.com/momenbasel/vulnhawk/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/momenbasel/vulnhawk.svg?style=social"></a>
</p>

<h1 align="center">VulnHawk</h1>

<p align="center">
  <strong>AI-powered code security scanner that finds vulnerabilities<br>Semgrep and CodeQL miss.</strong>
</p>

<p align="center">
  VulnHawk uses AI to understand your code's <em>business logic</em> - not just pattern matching.<br>
  It spots missing auth checks, IDOR flaws, and logic bugs that rule-based tools can't detect.
</p>

<p align="center">
  <strong>FREE for Claude Code / Codex subscribers - no API key needed.</strong>
</p>

---

## Installation

**CLI via PyPI:**
```bash
pip install vulnhawk
```

**GitHub Action via Marketplace:**
```yaml
# Using Claude Code (FREE for subscribers - no API costs!)
- uses: momenbasel/vulnhawk@v0.1.0
  with:
    target: '.'
    backend: 'claude-code'
    claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}

# Or using Anthropic API
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

## Why VulnHawk?

Traditional SAST tools (Semgrep, CodeQL, Bandit, SonarQube) use pattern matching and AST rules. They find known patterns but **cannot understand intent**.

VulnHawk analyzes your code with AI and cross-references how different parts of your codebase handle security. If 12 endpoints check authorization but one doesn't, VulnHawk catches it.

## VulnHawk vs Other SAST Tools

| Capability | VulnHawk | Semgrep | CodeQL | Snyk Code | Checkmarx | SonarQube |
|---|---|---|---|---|---|---|
| **Detection approach** | AI code understanding | Pattern matching (AST) | Data flow analysis (QL) | ML + rules | Pattern + data flow | Pattern matching |
| **Business logic bugs** | Yes - detects missing auth, IDOR, logic flaws | No | Limited | Limited | Limited | No |
| **Cross-file context** | Automatic - compares similar code patterns | Requires custom rules | Requires QL queries | Partial | Yes (paid) | Limited |
| **Setup complexity** | Zero config | Rules config | Database build + queries | Config file | Complex setup + licensing | Server + config |
| **Fix suggestions** | Context-specific code fixes with attack scenarios | Generic rule descriptions | Query-based descriptions | Generic patches | Generic recommendations | Rule-based tips |
| **Custom rules needed** | No - AI understands intent | Yes - must write YAML rules | Yes - must write QL queries | Partial | Yes | Yes |
| **PHP / Laravel support** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Ruby / Rails support** | Yes | Yes | Yes | Yes | Yes | Yes |
| **False positive rate** | Low - validates with attack scenarios | Medium - pattern matches can be noisy | Low - but misses logic bugs | Medium | Medium-High | High |
| **Pricing** | Free (Claude Code/Codex) / $0.50-$2 per scan (API) / Free (Ollama) | Free (OSS) / Paid (Team) | Free (OSS) / Paid (Advanced) | Free (limited) / $$$ | $$$$$ (enterprise only) | Free (Community) / $$$ |
| **CI/CD integration** | GitHub Action (1 line) | GitHub Action | GitHub Action | GitHub Action | Plugins | Plugins |
| **Local/private scanning** | Yes (Ollama backend) | Yes | Yes | No (cloud) | No (cloud) | Self-hosted |
| **Finds what others miss** | Missing auth on 1-of-N endpoints, IDOR chains, stored input misuse, logic bypasses | Known code patterns only | Data flow sinks only | Known patterns + some ML | Known patterns + data flow | Known code smells |

### What VulnHawk catches that others don't

- **Missing authorization**: 12 endpoints check `user.is_admin` but one doesn't - VulnHawk cross-references and flags it
- **IDOR / BOLA**: User ID from JWT vs user ID in URL parameter - VulnHawk understands the mismatch
- **Logic flaws**: Payment amount set client-side, order state machine bypass, race conditions in balance updates
- **Inconsistent validation**: Input sanitized in 5 handlers but raw in the 6th
- **Stored input misuse**: User input saved safely but later used in `eval()`, `exec()`, or raw SQL 3 files away

### When to use VulnHawk alongside traditional tools

VulnHawk is **not a replacement** for Semgrep/CodeQL - it's the layer on top. Use the combination:

| Tool | Best for |
|---|---|
| **Semgrep** | Known vulnerability patterns at scale, CI gatekeeping on known-bad patterns |
| **CodeQL** | Deep data flow analysis, taint tracking across complex call chains |
| **VulnHawk** | Business logic bugs, missing auth, IDOR, inconsistencies that rules can't express |

## Quick Start

```bash
pip install vulnhawk
```

### Option 1: Claude Code CLI (FREE for subscribers - RECOMMENDED)

If you have a Claude Code subscription (Max or Team), you already have everything you need:

```bash
# Make sure claude CLI is installed and authenticated
npm install -g @anthropic-ai/claude-code
claude login

# Scan with zero API costs
vulnhawk scan ./src -b claude-code
```

This uses your existing Claude Code subscription. No API key. No per-token billing. Completely free.

### Option 2: Codex CLI (FREE for ChatGPT Pro/Plus subscribers)

If you have a ChatGPT Pro or Plus subscription:

```bash
# Make sure codex CLI is installed and authenticated
npm install -g @openai/codex
codex login

# Scan with zero API costs
vulnhawk scan ./src -b codex
```

> **Note**: Claude Code backend is recommended over Codex for security analysis quality. Use Codex if you only have an OpenAI subscription.

### Option 3: API Key

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # Claude (default, best results)
# or
export OPENAI_API_KEY=sk-...           # OpenAI
```

```bash
vulnhawk scan ./src
```

### Option 4: Ollama (free, local, private)

```bash
ollama serve
vulnhawk scan ./src -b ollama -m llama3.1
```

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
# Claude Code CLI (FREE for subscribers - recommended)
vulnhawk scan ./src -b claude-code

# Codex CLI (FREE for ChatGPT Pro/Plus - good alternative)
vulnhawk scan ./src -b codex

# Claude API (default, best results)
vulnhawk scan ./src -b claude

# OpenAI API
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

### Enrich with other SAST results (SARIF input)

Feed results from Semgrep, CodeQL, or any SARIF-producing tool into VulnHawk. It uses those findings as additional context to find **deeper vulnerabilities** - validating, expanding, and chaining findings that rule-based tools flagged.

```bash
# Run Semgrep first, then feed results to VulnHawk
semgrep --config auto ./src -o semgrep.sarif --sarif
vulnhawk scan ./src --sarif-input semgrep.sarif

# Or chain CodeQL results
vulnhawk scan ./src --sarif-input codeql-results.sarif

# Combine with any scan mode
vulnhawk scan ./src --mode injection --sarif-input semgrep.sarif
```

**What this does:**
- VulnHawk reads the SARIF findings and injects them as context into every analysis prompt
- The AI validates whether the other tool's findings are real or false positives
- It looks for **related vulnerabilities** near flagged locations
- It builds **multi-step attack chains** connecting findings from different tools
- It checks whether suggested fixes actually address the root cause

**In CI/CD** - run Semgrep first (fast, free), then feed its output to VulnHawk for deep analysis:

```yaml
steps:
  - uses: actions/checkout@v4

  # Step 1: Fast Semgrep scan
  - name: Semgrep
    uses: returntocorp/semgrep-action@v1
    with:
      config: auto
      generateSarif: true

  # Step 2: Feed Semgrep results to VulnHawk for deep AI analysis
  - name: VulnHawk (enriched)
    uses: momenbasel/vulnhawk@main
    with:
      target: '.'
      backend: 'claude-code'
      claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
      sarif-input: 'semgrep.sarif'
```

### Preview what will be scanned
```bash
vulnhawk info ./src
```

## GitHub Action

VulnHawk is designed to run as a **full initial baseline scan** on your default branch, then **incrementally on every PR** to catch new vulnerabilities before they merge.

### Recommended Setup: Initial Scan + PR Scans

```yaml
name: VulnHawk Security Scan
on:
  push:
    branches: [main, master]   # Full baseline scan on default branch
  pull_request:                 # Incremental scan on every PR

permissions:
  security-events: write
  contents: read

jobs:
  vulnhawk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run VulnHawk
        uses: momenbasel/vulnhawk@main
        with:
          target: '.'
          backend: 'claude-code'
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          severity: 'medium'
          fail-on-findings: 'true'
```

This gives you:
- **Push to main/master**: Full codebase scan - establishes your security baseline and populates the Security tab
- **Every PR**: Scans the full repo with PR changes included - catches new vulnerabilities before merge
- **SARIF upload**: All findings appear in GitHub's **Security** > **Code Scanning** tab automatically

### Using Claude Code (FREE - no API costs)

```yaml
- uses: momenbasel/vulnhawk@main
  with:
    target: '.'
    backend: 'claude-code'
    claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

**Setup**: Run `claude config get oauth_token` locally, then add the value as a GitHub Actions secret named `CLAUDE_CODE_OAUTH_TOKEN`.

### Using Codex (FREE for ChatGPT subscribers)

```yaml
- uses: momenbasel/vulnhawk@main
  with:
    target: '.'
    backend: 'codex'
```

**Setup**: Codex uses OAuth from `codex login`. For CI, ensure the runner has Codex authenticated.

### Using Anthropic API

```yaml
- uses: momenbasel/vulnhawk@main
  with:
    target: '.'
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### PR-Only Scan (Lightweight)

If you only want to scan on pull requests:

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
          backend: 'claude-code'
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          severity: 'high'
          fail-on-findings: 'true'
```

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

| Language | Extensions | Framework-aware chunking |
|---|---|---|
| Python | `.py` | Django, Flask, FastAPI route detection |
| JavaScript | `.js`, `.jsx` | Express, Fastify, Next.js route detection |
| TypeScript | `.ts`, `.tsx` | Express, Fastify, NestJS route detection |
| Go | `.go` | `net/http` handler detection |
| Java | `.java` | Class and method splitting |
| PHP | `.php` | Laravel routes, class/trait/interface splitting |
| Ruby | `.rb`, `.erb` | Rails routes, class/module splitting |

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
| `CLAUDE_CODE_OAUTH_TOKEN` | OAuth token for Claude Code CLI backend (free for subscribers) |
| `ANTHROPIC_API_KEY` | API key for Claude API backend |
| `OPENAI_API_KEY` | API key for OpenAI backend |

## Cost Comparison

| Backend | Cost per scan (~100 files) | Requirements |
|---|---|---|
| **Claude Code CLI** | **$0 (free)** | Claude Code Max/Team subscription |
| **Codex CLI** | **$0 (free)** | ChatGPT Pro/Plus subscription |
| Claude API | ~$0.50-$2.00 | Anthropic API key + credits |
| OpenAI API | ~$1.00-$4.00 | OpenAI API key + credits |
| Ollama | $0 (free) | Local GPU (8GB+ VRAM recommended) |

## FAQ

**How is Claude Code CLI free?**
If you have a Claude Code subscription (Max at $100/mo or $200/mo, or Team plan), you get unlimited Claude usage through the CLI. VulnHawk pipes analysis prompts through your existing `claude` CLI, so there are no additional API costs.

**How is Codex CLI free?**
If you have a ChatGPT Pro ($200/mo) or Plus ($20/mo) subscription, Codex CLI usage is included. VulnHawk uses `codex exec` to run analysis non-interactively. Note: Claude Code backend produces better security analysis results and is recommended.

**How do I get my Claude Code OAuth token for CI?**
Run `claude config get oauth_token` on your local machine where you're logged into Claude Code. Add that token as a GitHub Actions secret named `CLAUDE_CODE_OAUTH_TOKEN`.

**Should I run VulnHawk on every PR or just on main?**
Both. Run on push to main/master for a full baseline that populates your Security tab, and on every PR to catch new issues before merge. The recommended workflow config above does both.

**Will it find everything?**
No security tool catches everything. VulnHawk is best at finding business logic bugs, missing authorization, and context-dependent vulnerabilities that pattern-matching tools miss. Use it alongside (not instead of) Semgrep/CodeQL.

**Is my code sent to an external API?**
Yes, code chunks are sent to the configured LLM provider (Anthropic, OpenAI). Use the Ollama backend for fully local, private scanning.

**Does it support monorepos?**
Yes. Point it at any directory and it will scan all supported files recursively.

**Does it support PHP and Ruby on Rails?**
Yes. VulnHawk has first-class support for PHP (including Laravel route detection, class/trait/interface splitting) and Ruby (including Rails route detection, class/module splitting). It understands framework-specific patterns like `Route::get()`, `resources`, and `before_action`.

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

VulnHawk is **source-available** under a custom license.

**Free for everyone** - individuals, teams, startups, and enterprises can use VulnHawk at no cost for internal security scanning, provided it is installed from an **official distribution channel**:
- [GitHub Marketplace](https://github.com/marketplace/actions/vulnhawk-security-scan)
- [PyPI](https://pypi.org/project/vulnhawk/)
- [This repository](https://github.com/momenbasel/vulnhawk)

**You cannot**: sell it, offer it as a paid/competing service, redistribute forks as your own product, or publish derivatives to any marketplace or registry.

GitHub forks are allowed **only** for submitting pull requests back to this repository.

See [LICENSE](LICENSE) for full terms.

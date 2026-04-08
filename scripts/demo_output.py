"""Generate demo terminal output for README screenshots."""

from rich.console import Console

from vulnhawk.models import Finding, ScanResult, Severity
from vulnhawk.reporters.terminal import render


def make_demo_result() -> ScanResult:
    return ScanResult(
        target="./src",
        findings=[
            Finding(
                title="SQL Injection in User Search",
                severity=Severity.CRITICAL,
                description=(
                    "User input is directly concatenated into SQL query string without "
                    "parameterization. An attacker can inject arbitrary SQL to dump the "
                    "entire database, bypass authentication, or execute system commands."
                ),
                file_path="src/routes/users.py",
                start_line=42,
                end_line=45,
                code_snippet='results = db.execute(f"SELECT * FROM users WHERE name LIKE \'%{query}%\'")',
                fix_suggestion=(
                    "Use parameterized queries:\n"
                    '  db.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{query}%",))'
                ),
                confidence=0.97,
                cwe_id="CWE-89",
                category="injection",
            ),
            Finding(
                title="Missing Authorization on Delete Endpoint",
                severity=Severity.CRITICAL,
                description=(
                    "The DELETE /api/users/:id endpoint has no authentication or authorization "
                    "check. All other user endpoints (GET, PUT, PATCH) use verify_auth() middleware "
                    "but this endpoint was missed. Any unauthenticated user can delete any account."
                ),
                file_path="src/routes/users.py",
                start_line=67,
                end_line=73,
                code_snippet=(
                    '@app.delete("/api/users/<user_id>")\n'
                    "def delete_user(user_id):\n"
                    '    db.execute("DELETE FROM users WHERE id = ?", (user_id,))\n'
                    '    return {"deleted": True}'
                ),
                fix_suggestion=(
                    "Add authentication decorator matching other endpoints:\n"
                    '  @app.delete("/api/users/<user_id>")\n'
                    "  @require_auth\n"
                    "  @require_role('admin')\n"
                    "  def delete_user(user_id): ..."
                ),
                confidence=0.95,
                cwe_id="CWE-862",
                category="authz",
            ),
            Finding(
                title="Hardcoded AWS Credentials",
                severity=Severity.HIGH,
                description=(
                    "AWS access key and secret key are hardcoded in source code. "
                    "These credentials provide access to the production AWS account."
                ),
                file_path="src/config.py",
                start_line=12,
                end_line=13,
                code_snippet=(
                    'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
                    'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
                ),
                fix_suggestion="Use environment variables or AWS IAM roles:\n  AWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY_ID']",
                confidence=0.93,
                cwe_id="CWE-798",
                category="secrets",
            ),
            Finding(
                title="Command Injection via Shell Execution",
                severity=Severity.HIGH,
                description=(
                    "User-controlled input is passed directly to shell command via subprocess "
                    "with shell=True. An attacker can inject arbitrary commands using "
                    "semicolons or backticks."
                ),
                file_path="src/utils/network.py",
                start_line=15,
                end_line=17,
                code_snippet='subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)',
                fix_suggestion=(
                    "Use subprocess with argument list (no shell):\n"
                    '  subprocess.run(["ping", "-c", "1", hostname], capture_output=True)'
                ),
                confidence=0.96,
                cwe_id="CWE-78",
                category="injection",
            ),
            Finding(
                title="Weak Password Hashing (MD5)",
                severity=Severity.MEDIUM,
                description=(
                    "MD5 is used for password hashing. MD5 is cryptographically broken and "
                    "can be reversed using rainbow tables in seconds."
                ),
                file_path="src/auth/passwords.py",
                start_line=8,
                end_line=9,
                code_snippet="return hashlib.md5(password.encode()).hexdigest()",
                fix_suggestion="Use bcrypt or argon2:\n  import bcrypt\n  return bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
                confidence=0.98,
                cwe_id="CWE-328",
                category="crypto",
            ),
        ],
        files_scanned=23,
        chunks_analyzed=87,
        scan_duration=14.3,
        llm_backend="claude",
    )


if __name__ == "__main__":
    console = Console(record=True, width=100)
    result = make_demo_result()

    console.print(f"\n[bold blue]VulnHawk v0.1.0[/bold blue]")
    console.print("[dim]AI-powered code security scanner[/dim]")
    console.print("[dim]Backend: claude | Mode: full | Min severity: low[/dim]\n")

    render(result, console)

    # Save SVG for README
    svg = console.export_svg(title="VulnHawk Scan Results")
    with open("docs/demo.svg", "w") as f:
        f.write(svg)
    print("\nSaved docs/demo.svg")

    # Also save text version
    text = console.export_text()
    with open("docs/demo.txt", "w") as f:
        f.write(text)
    print("Saved docs/demo.txt")

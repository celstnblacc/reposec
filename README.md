# RepoSec

Reusable security audit tool for any repository. Scans shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files for **34 vulnerability patterns** derived from real audit findings.

## Install

### From PyPI

```bash
python -m pip install reposec
```

### Recommended: Using pipx (CLI tool)

```bash
pipx install git+https://github.com/celstnblacc/reposec.git
```

This installs RepoSec in an isolated environment with global command access.

### From source (development)

```bash
git clone https://github.com/celstnblacc/reposec.git
cd reposec
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### In a project (virtual environment)

```bash
python -m venv .venv
source .venv/bin/activate
pip install git+https://github.com/celstnblacc/reposec.git
```

### Install from GitHub (correct URL syntax)

```bash
pip install "git+https://github.com/celstnblacc/reposec.git"
```

You can pin to a branch/tag/commit:

```bash
pip install "git+https://github.com/celstnblacc/reposec.git@main"
pip install "git+https://github.com/celstnblacc/reposec.git@efbd130"
```

After install:

```bash
reposec --version
reposec scan .
```

## Quick Start

```bash
# Scan current directory
reposec scan .

# Scan with JSON output (for CI pipelines)
reposec scan . --format json

# Only show critical and high findings
reposec scan . --severity high

# Generate markdown report (for PR comments)
reposec scan . --format markdown --output report.md

# List all 34 rules with descriptions
reposec list-rules

# Create a config file
reposec init
```

## Rules (34 total)

| Category | Count | IDs | Examples |
|----------|-------|-----|----------|
| Shell | 9 | SHELL-001 to SHELL-009 | eval injection, unquoted vars, bash -c interpolation |
| Python | 9 | PY-001 to PY-009 | zip slip, yaml.load, eval/exec, SQL injection |
| JavaScript | 8 | JS-001 to JS-008 | eval, path traversal, prototype pollution, XSS |
| GitHub Actions | 5 | GHA-001 to GHA-005 | workflow injection, unpinned actions, secrets in logs |
| Config | 3 | CFG-001 to CFG-003 | auto-approve, committed .env, permissive CORS |

Run `reposec list-rules` or `reposec list-rules --format json` for full details.

## Configuration

Create `.reposec.yml` in your project root (or run `reposec init`):

```yaml
# Minimum severity to report: critical, high, medium, low
severity_threshold: medium

# Glob patterns for paths to exclude
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/fixtures/**"

# Rule IDs to disable
disable_rules:
  - SHELL-008

# Additional directories containing custom rule modules
custom_rules_dirs: []
```

CLI flags override config file values.

## Inline Suppression

Suppress a finding on a specific line:

```python
eval(expr)  # reposec:ignore PY-003
```

Or on the line above:

```python
# reposec:ignore PY-003
eval(expr)
```

Multiple rules can be suppressed:

```bash
eval $cmd  # reposec:ignore SHELL-001, SHELL-002
```

## Output Formats

- **terminal** (default) — Rich color-coded table with severity highlighting and fix hints
- **json** — Machine-readable `{"findings": [...], "summary": {...}}` for CI integration
- **markdown** — Report grouped by severity level, suitable for PR comments

## CI Integration

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/celstnblacc/reposec
    rev: main
    hooks:
      - id: reposec
```

### GitHub Action

```yaml
- uses: celstnblacc/reposec@main
  with:
    severity: medium
    format: terminal
```

### Generic CI

```bash
pip install reposec
reposec scan . --severity high --format json
# Exit code 1 if findings exist, 0 if clean
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the severity threshold |
| 1 | One or more findings detected |

## Suppression Comments

Both `#` and `//` comment styles are supported:

```python
# Python / Shell
eval(expr)  # reposec:ignore PY-003
```

```javascript
// JavaScript
eval(code);  // reposec:ignore JS-001
```

```bash
# Shell
eval $cmd  # reposec:ignore SHELL-001
```

Suppress multiple rules:
```bash
eval $cmd  # reposec:ignore SHELL-001, SHELL-002
```

## About This Project

RepoSec was developed to package 34 security vulnerability patterns discovered during real-world audits of the [spec-kit](https://github.com/celstnblacc/spec-kit) and [superpowers](https://github.com/celstnblacc/superpowers) projects.

The rules focus on:
- **Command injection**: eval, exec, bash -c, sed, printf with unquoted variables
- **Path traversal**: Unvalidated path.join(), symlink following
- **Code/data injection**: YAML unsafe load, pickle, SQL string formatting
- **Supply chain**: Unpinned GitHub Actions, workflow injection
- **Configuration**: Committed .env files, overly permissive CORS, auto-approve settings

## Troubleshooting

### "Module not found" errors

If you get import errors, ensure you're in the correct environment:

```bash
# For pipx installations
pipx list  # Should show reposec

# For venv installations
source .venv/bin/activate
which reposec  # Should show venv path
```

### Pre-commit hook not running

Ensure `.pre-commit-hooks.yaml` is in the correct location and hooks are configured:

```bash
pre-commit install
pre-commit run --all-files  # Test manually
```

## Development

To contribute or modify rules:

```bash
git clone https://github.com/celstnblacc/reposec.git
cd reposec
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Test the CLI
reposec scan tests/fixtures/
```

New rules should be added to `src/reposec/rules/` with the `@register` decorator:

```python
from reposec.models import Finding, Severity
from reposec.rules import register

@register(
    id="RULE-001",
    name="rule-description",
    severity=Severity.HIGH,
    description="What this rule detects",
    extensions=[".py"],
    cwe_id="CWE-123"
)
def rule_001_check(file_path, content, config=None):
    findings = []
    # Detection logic here
    return findings
```

## License

MIT

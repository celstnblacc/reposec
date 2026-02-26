# RepoSec

Reusable security audit tool for any repository. Scans shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files for **34 vulnerability patterns** derived from real audit findings.

## Install

```bash
pip install reposec
```

Or install from source:

```bash
git clone https://github.com/DevOpsCelstn/reposec.git
cd reposec
pip install -e ".[dev]"
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
  - repo: https://github.com/DevOpsCelstn/reposec
    rev: v0.1.0
    hooks:
      - id: reposec
```

### GitHub Action

```yaml
- uses: DevOpsCelstn/reposec@v0.1.0
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

## License

MIT

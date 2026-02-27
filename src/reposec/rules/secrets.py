"""Secrets security rules (SEC-001 through SEC-003)."""

from __future__ import annotations

import re
from pathlib import Path

from reposec.models import Finding, Severity
from reposec.rules import register

SECRETS_EXTS = [".yml", ".yaml", ".json", ".env", ".conf", ".cfg", ".ini", ".toml"]


def _skip_false_positive(line: str) -> bool:
    """Check if a line should be skipped as a false positive."""
    line_upper = line.upper()
    # Skip comments
    if line.lstrip().startswith("#"):
        return True
    # Skip obvious placeholders (with clear markers like _NOT_REAL, _PLACEHOLDER)
    if any(
        keyword in line_upper
        for keyword in ["_NOT_REAL", "_PLACEHOLDER", "YOUR_", "CHANGE_ME", "REPLACE_ME"]
    ):
        return True
    # Skip environment variable references
    if "$" in line or "${" in line or "${{" in line:
        return True
    # Skip template syntax
    if "<" in line or ">" in line:
        return True
    return False


@register(
    id="SEC-001",
    name="aws-access-key-id",
    severity=Severity.CRITICAL,
    description="Detects AWS access key ID (AKIA*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_001_aws_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # AWS access keys start with AKIA followed by 16 alphanumeric characters
    pattern = re.compile(r"AKIA[0-9A-Z]{16}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        matches = pattern.finditer(line)
        for match in matches:
            findings.append(
                Finding(
                    rule_id="SEC-001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="AWS access key ID detected in file",
                    cwe_id="CWE-798",
                    fix_hint="Remove the key and rotate it in AWS IAM; use environment variables instead",
                )
            )
    return findings


@register(
    id="SEC-002",
    name="gcp-api-key",
    severity=Severity.CRITICAL,
    description="Detects GCP API key (AIza*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_002_gcp_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # GCP API keys start with AIza followed by 35 alphanumeric/special characters
    pattern = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        matches = pattern.finditer(line)
        for match in matches:
            findings.append(
                Finding(
                    rule_id="SEC-002",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="GCP API key detected in file",
                    cwe_id="CWE-798",
                    fix_hint="Remove the key and rotate it in GCP Console; use environment variables instead",
                )
            )
    return findings


@register(
    id="SEC-003",
    name="github-token",
    severity=Severity.CRITICAL,
    description="Detects GitHub personal access tokens (ghp_*, gho_*, ghu_*, ghs_*, ghr_*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_003_github_token(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # GitHub tokens start with specific prefixes followed by 36+ characters
    pattern = re.compile(r"(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        matches = pattern.finditer(line)
        for match in matches:
            findings.append(
                Finding(
                    rule_id="SEC-003",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="GitHub personal access token detected in file",
                    cwe_id="CWE-798",
                    fix_hint="Revoke the token at github.com/settings/tokens; use GITHUB_TOKEN env var in CI",
                )
            )
    return findings

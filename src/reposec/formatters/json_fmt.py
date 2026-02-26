"""JSON formatter for RepoSec scan results."""

from __future__ import annotations

import json

from reposec.models import ScanResult


def format_json(result: ScanResult, **_kwargs) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)

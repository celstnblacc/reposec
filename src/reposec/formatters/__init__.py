"""Output formatters for RepoSec scan results."""

from __future__ import annotations

from reposec.formatters.json_fmt import format_json
from reposec.formatters.markdown import format_markdown
from reposec.formatters.terminal import format_terminal

__all__ = ["format_terminal", "format_json", "format_markdown", "get_formatter"]

FORMATTERS = {
    "terminal": format_terminal,
    "json": format_json,
    "markdown": format_markdown,
}


def get_formatter(name: str):
    """Get a formatter function by name."""
    if name not in FORMATTERS:
        raise ValueError(f"Unknown format: {name!r}. Choose from: {', '.join(FORMATTERS)}")
    return FORMATTERS[name]

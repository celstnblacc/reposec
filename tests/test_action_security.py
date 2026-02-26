"""Security checks for GitHub Action wrapper."""

from pathlib import Path


def test_action_uses_array_invocation_not_eval_like_command_string():
    content = Path("action.yml").read_text(encoding="utf-8")
    assert 'ARGS=(scan "${{ inputs.path }}" --severity "${{ inputs.severity }}" --format "${{ inputs.format }}")' in content
    assert 'reposec "${ARGS[@]}"' in content
    assert "$ARGS" not in content


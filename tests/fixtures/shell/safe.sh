#!/bin/bash
set -euo pipefail

# Safe: trap for cleanup
tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

# Safe: quoted GITHUB_OUTPUT
echo "result=value" >> "$GITHUB_OUTPUT"

# Safe: using jq for JSON
jq -n --arg name "$name" '{"name": $name}'

# Safe: no eval
echo "hello world"

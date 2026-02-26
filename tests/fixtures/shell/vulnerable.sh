#!/bin/bash

# SHELL-001: eval injection
eval $(get_user_input)
eval "$( echo $data )"

# SHELL-003: bash -c interpolation
bash -c "echo $user_data"

# SHELL-004: sed replacement injection
sed "s/old/$user_input/g" file.txt

# SHELL-005: json printf injection
printf '{"name":"%s","value":"%s"}' "$name" "$value"

# SHELL-002: unquoted variable in dangerous command
rm -rf $user_dir

# SHELL-006: unquoted GITHUB_OUTPUT
echo "result=value" >> $GITHUB_OUTPUT

# SHELL-007: mktemp without trap
tmpfile=$(mktemp)
echo "data" > "$tmpfile"

# SHELL-008: missing set -euo (already triggered by shebang with no set -e)

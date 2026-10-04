#!/usr/bin/env bash
#
# Batch-analyze a file of passwords (one per line) using password_analyzer.py.
# Usage: ./check_passwords.sh passwords.txt
#
# For authorised auditing and learning only.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <password-list-file>"
    exit 1
fi

FILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$FILE" ]]; then
    echo "[!] File not found: $FILE"
    exit 1
fi

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    count=$((count + 1))
    echo "############################################################"
    echo "# Password #$count"
    # Pipe the password in instead of passing it as an argument, so it never
    # shows up in the process list (ps) for other users on the machine.
    printf '%s\n' "$line" | python3 "$SCRIPT_DIR/password_analyzer.py" --stdin
done < "$FILE"

echo "[+] Analyzed $count password(s)."

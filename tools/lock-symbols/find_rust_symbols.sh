#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_FILE="${RUST_MUTEX_SYMBOLS_PATH:-$ROOT_DIR/output/rust_mutex_symbols.txt}"

if [[ $# -lt 1 ]]; then
    cat <<EOF
Usage: $(basename "$0") <binary-or-library> [more paths...]

Scans binaries/libraries for likely Rust mutex lock/unlock symbols and writes:
  source,library,symbol,phase

to: $OUT_FILE
EOF
    exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

{
    echo "# source,library,symbol,phase"
    echo "# source: rust_std|parking_lot"
    echo "# phase: lock|unlock"
} > "$OUT_FILE"

for path in "$@"; do
    if [[ ! -r "$path" ]]; then
        echo "[warn] skipping unreadable path: $path" >&2
        continue
    fi

    # Use nm without -D to catch both dynamic and static symbols (Rust uses static symbols)
    nm --defined-only "$path" 2>/dev/null | awk '{print $3}' | \
        grep -E 'Mutex|mutex|parking_lot|lock|unlock' | sort -u | while IFS= read -r sym; do
            [[ -z "$sym" ]] && continue

            src="rust_std"
            phase="lock"
            lower="$(printf '%s' "$sym" | tr '[:upper:]' '[:lower:]')"

            if [[ "$lower" == *"parking_lot"* ]]; then
                src="parking_lot"
            fi
            if [[ "$lower" == *"unlock"* ]]; then
                phase="unlock"
            fi

            printf '%s,%s,%s,%s\n' "$src" "$path" "$sym" "$phase"
        done >> "$OUT_FILE"
done

sort -u -t, -k1,4 "$OUT_FILE" -o "$OUT_FILE"
echo "[ok] wrote symbol targets to $OUT_FILE"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN_DIR="$ROOT/src/scanners/network/domain"
BASE_OUT="$DOMAIN_DIR/resolvers-base.txt"
EXTRAS="$DOMAIN_DIR/resolvers-extras.txt"
MERGED="$DOMAIN_DIR/resolvers-default.txt"
TRUSTED="$DOMAIN_DIR/resolvers-trusted.txt"
META="$DOMAIN_DIR/resolvers-default.meta.json"
MERGE_PY="$ROOT/scripts/merge_domain_resolvers.py"
VALIDATE_PY="$ROOT/scripts/validate_domain_resolvers.py"
INTERVAL_DAYS="${DXCAN_DOMAIN_UPDATE_DAYS:-7}"
VALIDATE_LIMIT="${DXCAN_DOMAIN_VALIDATE_LIMIT:-512}"
VALIDATE_WORKERS="${DXCAN_DOMAIN_VALIDATE_WORKERS:-400}"
VALIDATE_TIMEOUT="${DXCAN_DOMAIN_VALIDATE_TIMEOUT:-0.8}"
FORCE=0
MERGE_ONLY=0
VALIDATE_ONLY=0
CHECK=0
VALIDATE=1
BASE_URL="${DXCAN_DOMAIN_RESOLVERS_BASE_URL:-https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Refresh the vendored domain resolver list from a public upstream list + resolvers-extras.txt.

By default runs only when the last update is older than ${INTERVAL_DAYS} days
or the fetched base copy is newer than the vendored base file.

Options:
  --force       Update now regardless of age
  --merge-only  Re-merge resolvers-base.txt + extras (no fetch)
  --validate-only  Re-validate resolvers-default.txt into resolvers-trusted.txt
  --no-validate Skip UDP validation after merge
  --check       Exit 0 if up to date, 1 if an update is due
  -h, --help    Show this help

Environment:
  DXCAN_DOMAIN_UPDATE_DAYS          Minimum days between updates (default: 7)
  DXCAN_DOMAIN_RESOLVERS_BASE_URL   Upstream resolver list URL
  DXCAN_DOMAIN_RESOLVERS_BASE       Local file used instead of fetch
  DXCAN_DOMAIN_VALIDATE_LIMIT       Max trusted resolvers kept (default: 512)
  DXCAN_DOMAIN_VALIDATE_WORKERS     Validation concurrency (default: 400)
  DXCAN_DOMAIN_VALIDATE_TIMEOUT     Validation probe timeout seconds (default: 0.8)

Cron example (weekly, Sunday 03:30):
  30 3 * * 0 cd $ROOT && ./scripts/update-domain-resolvers.sh
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=1 ;;
        --merge-only) MERGE_ONLY=1 ;;
        --validate-only) VALIDATE_ONLY=1 ;;
        --no-validate) VALIDATE=0 ;;
        --check) CHECK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[error] unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

meta_epoch() {
    python3 - "$META" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print(0)
else:
    try:
        print(int(json.loads(p.read_text()).get("updated_at_epoch", 0)))
    except Exception:
        print(0)
PY
}

base_mtime_epoch() {
    python3 - "$META" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print(0)
else:
    try:
        print(int(json.loads(p.read_text()).get("base_mtime_epoch", 0)))
    except Exception:
        print(0)
PY
}

source_mtime() {
    stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1"
}

update_due() {
    if [ "$FORCE" -eq 1 ]; then
        return 0
    fi
    local now last interval_secs
    now=$(date +%s)
    last=$(meta_epoch)
    interval_secs=$((INTERVAL_DAYS * 86400))
    if [ "$last" -eq 0 ] || [ $((now - last)) -ge "$interval_secs" ]; then
        return 0
    fi
    if [ "$MERGE_ONLY" -eq 1 ]; then
        return 1
    fi
    if [ ! -f "$BASE_OUT" ]; then
        return 0
    fi
    return 1
}

copy_sidecars() {
    mkdir -p "$ROOT/target"
    if [ -f "$TRUSTED" ]; then
        cp "$TRUSTED" "$ROOT/target/resolvers.txt"
        cp "$TRUSTED" "$ROOT/target/resolvers-trusted.txt"
    elif [ -f "$MERGED" ]; then
        cp "$MERGED" "$ROOT/target/resolvers.txt"
    fi
}

run_validate() {
    if [ ! -f "$MERGED" ]; then
        echo "[error] merged resolver list missing: $MERGED" >&2
        exit 1
    fi
    echo "[validate] $MERGED -> $TRUSTED (limit ${VALIDATE_LIMIT})"
    python3 "$VALIDATE_PY" \
        "$MERGED" "$TRUSTED" \
        --workers "$VALIDATE_WORKERS" \
        --timeout "$VALIDATE_TIMEOUT" \
        --limit "$VALIDATE_LIMIT"
    copy_sidecars
}

finish_update() {
    if [ "$VALIDATE" -eq 1 ]; then
        run_validate
        echo "[done] $(wc -l < "$TRUSTED") trusted resolvers in $TRUSTED"
    else
        echo "[done] $(wc -l < "$MERGED") resolvers in $MERGED"
    fi
}

run_merge() {
    local base_source="${1:-$BASE_OUT}"
    local base_url="${2:-}"
    python3 "$MERGE_PY" \
        --base "$BASE_OUT" \
        --extras "$EXTRAS" \
        --out "$MERGED" \
        --meta "$META" \
        --base-source "$base_source" \
        --base-url "$base_url"
    copy_sidecars
}

fetch_base() {
    if [ -n "${DXCAN_DOMAIN_RESOLVERS_BASE:-}" ] && [ -f "${DXCAN_DOMAIN_RESOLVERS_BASE}" ]; then
        echo "[fetch] ${DXCAN_DOMAIN_RESOLVERS_BASE} -> $BASE_OUT"
        cp "${DXCAN_DOMAIN_RESOLVERS_BASE}" "$BASE_OUT"
        echo "${DXCAN_DOMAIN_RESOLVERS_BASE}"
        return 0
    fi
    echo "[fetch] $BASE_URL -> $BASE_OUT"
    curl -fsSL "$BASE_URL" -o "$BASE_OUT"
    echo "$BASE_URL"
}

if [ ! -f "$EXTRAS" ]; then
    echo "[error] extras file missing: $EXTRAS" >&2
    exit 1
fi

if [ "$CHECK" -eq 1 ]; then
    if update_due; then
        echo "[check] domain resolver update is due"
        exit 1
    fi
    echo "[check] domain resolver list is up to date"
    exit 0
fi

if [ "$VALIDATE_ONLY" -eq 1 ]; then
    run_validate
    exit 0
fi

if [ "$MERGE_ONLY" -eq 1 ]; then
    if [ ! -f "$BASE_OUT" ]; then
        echo "[error] vendored base missing: $BASE_OUT (run without --merge-only first)" >&2
        exit 1
    fi
    echo "[merge] re-merging $BASE_OUT + $EXTRAS"
    run_merge "$BASE_OUT" ""
    finish_update
    exit 0
fi

if ! update_due; then
    echo "[skip] domain resolvers fresh (interval ${INTERVAL_DAYS}d, use --force to override)"
    if [ -f "$MERGED" ]; then
        copy_sidecars
    fi
    exit 0
fi

if ! SRC=$(fetch_base); then
    if [ -f "$BASE_OUT" ] && [ -f "$MERGED" ]; then
        echo "[warn] resolver fetch failed; keeping existing vendored files" >&2
        exit 0
    fi
    echo "[error] could not fetch resolver base list" >&2
    exit 1
fi

echo "[merge] $BASE_OUT + $EXTRAS -> $MERGED"
run_merge "$SRC" "$BASE_URL"
finish_update

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VHOST_DIR="$ROOT/src/scanners/network/vhost"
BASE_OUT="$VHOST_DIR/vhost-base.txt"
EXTRAS="$VHOST_DIR/vhost-extras.txt"
MERGED="$VHOST_DIR/vhost-wordlist.txt"
META="$VHOST_DIR/vhost-wordlist.meta.json"
MERGE_PY="$ROOT/scripts/merge_vhost_wordlist.py"
INTERVAL_DAYS="${DXCAN_VHOST_UPDATE_DAYS:-7}"
FORCE=0
MERGE_ONLY=0
CHECK=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Refresh the vendored vhost wordlist from nmap vhosts-full.lst + vhost-extras.txt.

By default runs only when the last update is older than ${INTERVAL_DAYS} days
or the installed nmap list is newer than the vendored base copy.

Options:
  --force       Update now regardless of age
  --merge-only  Re-merge vhost-base.txt + extras (no nmap fetch)
  --check       Exit 0 if up to date, 1 if an update is due
  -h, --help    Show this help

Environment:
  DXCAN_VHOST_UPDATE_DAYS   Minimum days between updates (default: 7)
  DXCAN_VHOST_WORDLIST_BASE Override nmap source path

Cron example (weekly, Sunday 03:00):
  0 3 * * 0 cd $ROOT && ./scripts/update-vhost-wordlist.sh
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=1 ;;
        --merge-only) MERGE_ONLY=1 ;;
        --check) CHECK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[error] unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

find_nmap_base() {
    local candidate
    for candidate in \
        "${DXCAN_VHOST_WORDLIST_BASE:-}" \
        /usr/share/nmap/nselib/data/vhosts-full.lst \
        /usr/local/share/nmap/nselib/data/vhosts-full.lst
    do
        [ -n "$candidate" ] && [ -f "$candidate" ] || continue
        echo "$candidate"
        return 0
    done
    return 1
}

nmap_version() {
    nmap --version 2>/dev/null | head -1 | awk '{print $3}' | tr -d '()' || true
}

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
    local now last interval_secs src_m stored_m
    now=$(date +%s)
    last=$(meta_epoch)
    interval_secs=$((INTERVAL_DAYS * 86400))
    if [ "$last" -eq 0 ] || [ $((now - last)) -ge "$interval_secs" ]; then
        return 0
    fi
    if [ "$MERGE_ONLY" -eq 1 ]; then
        return 1
    fi
    local src
    src=$(find_nmap_base) || return 1
    src_m=$(source_mtime "$src")
    stored_m=$(base_mtime_epoch)
    if [ "$src_m" -gt "$stored_m" ]; then
        return 0
    fi
    return 1
}

copy_sidecars() {
    mkdir -p "$ROOT/target"
    cp "$MERGED" "$ROOT/target/vhost-wordlist.txt"
}

run_merge() {
    local base_source="${1:-$BASE_OUT}"
    python3 "$MERGE_PY" \
        --base "$BASE_OUT" \
        --extras "$EXTRAS" \
        --out "$MERGED" \
        --meta "$META" \
        --base-source "$base_source" \
        --nmap-version "$(nmap_version)"
    copy_sidecars
}

if [ ! -f "$EXTRAS" ]; then
    echo "[error] extras file missing: $EXTRAS" >&2
    exit 1
fi

if [ "$CHECK" -eq 1 ]; then
    if update_due; then
        echo "[check] vhost wordlist update is due"
        exit 1
    fi
    echo "[check] vhost wordlist is up to date"
    exit 0
fi

if [ "$MERGE_ONLY" -eq 1 ]; then
    if [ ! -f "$BASE_OUT" ]; then
        echo "[error] vendored base missing: $BASE_OUT (run without --merge-only first)" >&2
        exit 1
    fi
    echo "[merge] re-merging $BASE_OUT + $EXTRAS"
    run_merge "$BASE_OUT"
    exit 0
fi

if ! update_due; then
    echo "[skip] vhost wordlist fresh (interval ${INTERVAL_DAYS}d, use --force to override)"
    if [ -f "$MERGED" ]; then
        copy_sidecars
    fi
    exit 0
fi

SRC=$(find_nmap_base) || {
    if [ -f "$BASE_OUT" ] && [ -f "$MERGED" ]; then
        echo "[warn] nmap vhosts-full.lst not found; keeping existing vendored files" >&2
        exit 0
    fi
    echo "[error] nmap vhosts-full.lst not found. Install nmap or set DXCAN_VHOST_WORDLIST_BASE." >&2
    exit 1
}

echo "[fetch] $SRC -> $BASE_OUT"
cp "$SRC" "$BASE_OUT"
echo "[merge] $BASE_OUT + $EXTRAS -> $MERGED"
run_merge "$SRC"
echo "[done] $(wc -l < "$MERGED") entries in $MERGED"

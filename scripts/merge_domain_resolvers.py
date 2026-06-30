#!/usr/bin/env python3
import argparse
import json
import ipaddress
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_ips(raw: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in raw.splitlines():
        token = line.split("#", 1)[0].strip().split()[0] if line.strip() else ""
        if not token:
            continue
        try:
            ip = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return sorted(out, key=lambda s: ipaddress.ip_address(s))


def merge_text(base_raw: str, extras_raw: str) -> tuple[str, int, int, int]:
    base = parse_ips(base_raw)
    extras_only = [ip for ip in parse_ips(extras_raw) if ip not in set(base)]
    merged = sorted(set(base) | set(extras_only), key=lambda s: ipaddress.ip_address(s))
    body = "\n".join(merged) + ("\n" if merged else "")
    return body, len(base), len(extras_only), len(merged)


def main() -> int:
    ap = argparse.ArgumentParser(description="Merge public resolver base + dxcan extras")
    ap.add_argument("--base", type=Path, required=True)
    ap.add_argument("--extras", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--meta", type=Path)
    ap.add_argument("--base-source", default="")
    ap.add_argument("--base-url", default="")
    args = ap.parse_args()

    base_raw = args.base.read_text(encoding="utf-8", errors="replace")
    extras_raw = args.extras.read_text(encoding="utf-8", errors="replace")
    merged, base_n, extras_n, merged_n = merge_text(base_raw, extras_raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(merged, encoding="utf-8")

    if args.meta:
        base_mtime = int(args.base.stat().st_mtime) if args.base.is_file() else 0
        now = datetime.now(timezone.utc)
        payload = {
            "updated_at": now.isoformat(),
            "updated_at_epoch": int(now.timestamp()),
            "interval_days": 7,
            "base_file": str(args.base),
            "base_source": args.base_source or str(args.base),
            "base_url": args.base_url,
            "base_mtime_epoch": base_mtime,
            "base_entries": base_n,
            "extras_file": str(args.extras),
            "extras_entries": extras_n,
            "merged_file": str(args.out),
            "merged_entries": merged_n,
        }
        args.meta.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"merged {merged_n} resolvers -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

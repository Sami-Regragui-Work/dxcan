#!/usr/bin/env python3
import argparse
import ipaddress
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def encode_query(name: str, qid: int) -> bytes:
    parts = [p for p in name.strip(".").split(".") if p]
    out = bytearray()
    out.extend(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0))
    for part in parts:
        label = part.encode("ascii")
        out.append(len(label))
        out.extend(label)
    out.append(0)
    out.extend(struct.pack("!HH", 1, 1))
    return bytes(out)


def probe_resolver(ip: str, timeout: float, qname: str) -> tuple[str, float] | None:
    payload = encode_query(qname, random.randint(1, 65535))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.sendto(payload, (ip, 53))
        data, _ = sock.recvfrom(512)
    except OSError:
        return None
    finally:
        sock.close()
    if len(data) < 12:
        return None
    elapsed = time.perf_counter() - start
    return ip, elapsed


def load_ips(path: Path) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
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
        ips.append(ip)
    return ips


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate DNS resolvers with UDP A probes")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--workers", type=int, default=400)
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--limit", type=int, default=512)
    ap.add_argument("--query-name", default="example.com")
    args = ap.parse_args()

    ips = load_ips(args.input)
    if not ips:
        print("[error] no resolvers in input", file=sys.stderr)
        return 1

    trusted: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(probe_resolver, ip, args.timeout, args.query_name): ip for ip in ips
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                trusted.append(result)

    trusted.sort(key=lambda row: row[1])
    if args.limit > 0:
        trusted = trusted[: args.limit]

    body = "\n".join(ip for ip, _ in trusted) + ("\n" if trusted else "")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    print(
        f"validated {len(trusted)}/{len(ips)} resolvers -> {args.output} "
        f"(timeout={args.timeout}s workers={args.workers})"
    )
    return 0 if trusted else 1


if __name__ == "__main__":
    sys.exit(main())

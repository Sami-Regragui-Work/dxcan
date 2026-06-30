# dxcan

Rust port scanner with optional service detection, role labels, and nmap-style OS fingerprinting (`--os`).

## Prerequisites

- Rust toolchain (`cargo`, edition 2021)
- Linux with raw sockets for SYN scans and `--os` (run with `sudo` or `CAP_NET_RAW`)
- **[Nmap](https://nmap.org/)** installed — provides `/usr/share/nmap/nmap-os-db` and `/usr/share/nmap/nselib/data/vhosts-full.lst`, used at build time; `--os` and `--vhost` prefer live files at runtime

Optional override:

```bash
export DXCAN_OS_DB=/path/to/nmap-os-db
```

## Build and install

```bash
cargo build --release
cargo install --path . --force
```

Build embeds a snapshot of the nmap OS database, the vendored vhost wordlist, and the vendored domain resolver list. Refresh those with `./scripts/update-vhost-wordlist.sh` and `./scripts/update-domain-resolvers.sh` (weekly by default; not on every build).

Optional overrides:

```bash
export DXCAN_OS_DB=/path/to/nmap-os-db
export DXCAN_VHOST_WORDLIST=/path/to/custom-wordlist.txt
export DXCAN_VHOST_UPDATE_DAYS=7
export DXCAN_DOMAIN_UPDATE_DAYS=7
export DXCAN_DOMAIN_RESOLVERS=/path/to/resolvers.txt
```

Use `--dev` for small smoke wordlists and dev resolver lists during local testing and bench runs.

Use the built binary without installing globally:

```bash
export PATH="$PWD/target/release:$PATH"
dxcan --version
```

## Quick start

Port scan (default: open ports only; SYN half-open when privileged):

```bash
sudo dxcan -H scanme.nmap.org -p 1-1024
```

All port states (closed, filtered) — full connect classification:

```bash
dxcan -H scanme.nmap.org -p 1-1024 --all
```

Scan method and verify (optional):

```bash
dxcan -H scanme.nmap.org -p 1-1024 --scan-method connect
sudo dxcan -H scanme.nmap.org -p 1-1024 --scan-method syn --verify
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--scan-method auto\|connect\|syn` | `auto` | `auto`: SYN open-only when root + IPv4; connect when `--all` |
| `--verify` | off | After SYN discovery, connect-confirm each open port |
| `--all` | off | Classify every port (closed/filtered); uses full connect scan |

Service versions:

```bash
dxcan -H scanme.nmap.org -p 22,80 --service-version
```

OS detection (requires nmap OS database and root). Text output uses an nmap-style block after the port table (`Device type:` / `Running:` / `OS CPE:` / `OS details:` / `OS match accuracy:`):

```bash
sudo dxcan -H scanme.nmap.org -p 22,80 --os
```

OS with banner-based product hints (compare to OpenVAS-style distro lines):

```bash
sudo dxcan -H scanme.nmap.org -p 22,80 --os --product-hints
sudo dxcan -H scanme.nmap.org -p 22,80 --os-rich
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--os` / `-O` | off | TCP/IP OS fingerprint only (no banner grab) |
| `--product-hints` | off | After `--os`, add `Product hint:` lines from service banners |
| `--os-rich` | off | Shorthand for `--os --product-hints` |

Service-rich output (versions, reverse DNS, role labels):

```bash
dxcan -H scanme.nmap.org -p 1-1024 --sv-rich
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--service-version` / `-s` | off | Probe open ports for service banners and versions |
| `--reverse-dns` | off | PTR lookup on the target IP |
| `--role-labels` | off | Heuristic role tags on known services |
| `--sv-rich` | off | Shorthand for `--service-version --reverse-dns --role-labels` |

JSON:

```bash
dxcan -H scanme.nmap.org -p 22,80 --service-version --json
```

Virtual host discovery (default wordlist: vendored nmap `vhosts-full.lst` + extras; refresh with `./scripts/update-vhost-wordlist.sh`):

```bash
dxcan -H scanme.nmap.org -p 80 --vhost
dxcan -H scanme.nmap.org -p 80 --vhost --vhost-wordlist /path/to/custom.txt
```

Domain discovery (default: vendored resolver list from `./scripts/update-domain-resolvers.sh`; use `--dev` for smoke lists):

```bash
dxcan -H example.com -p 53 --domain
dxcan -H example.com -p 53 --domain --dev
dxcan -H example.com -p 53 --domain --domain-resolvers ~/.config/dxcan/resolvers.txt
dxcan -H example.com -p 53 --domain --domain-rich
```

| Flag | Meaning |
|------|---------|
| `--dev` | Smoke wordlist + dev resolver list for local testing |
| `--domain-resolvers` | Explicit resolver file (overrides embedded defaults) |
| `--domain-max-inflight` | Cap concurrent UDP DNS queries (default scales with pool size) |
| `DXCAN_DOMAIN_RESOLVERS` | Same as `--domain-resolvers` via env |
| `--domain-rich` | CNAME/TTL/AAAA via Hickory (slower, richer) |

Production resolver list: refresh with `./scripts/update-domain-resolvers.sh` (Trickest public list + extras, vendored into the binary). Bench runs pass `--domain-resolvers bench/resolvers.txt` explicitly.

## Binaries

| Binary | Role |
|--------|------|
| `dxcan` | Native scanner |
| `dxcan-nmap` | nmap XML wrapper |
| `dxcan-rustscan` | rustscan + nmap wrapper |

## Benchmarks (local checkout)

Benchmark scripts under `bench/` and docs under `references/` are kept in the working tree but are not part of the minimal git export. If you have them locally, see `references/how-to-use.md` for `bench/doc.sh`, preflight, and OpenVAS wake workflows.

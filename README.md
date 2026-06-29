# dxcan

Rust port scanner with optional service detection, role labels, and nmap-style OS fingerprinting (`--os`).

## Prerequisites

- Rust toolchain (`cargo`, edition 2021)
- Linux with raw sockets for SYN scans and `--os` (run with `sudo` or `CAP_NET_RAW`)
- **[Nmap](https://nmap.org/)** installed — provides `/usr/share/nmap/nmap-os-db`, used at build time and for `--os` at runtime

Optional override:

```bash
export DXCAN_OS_DB=/path/to/nmap-os-db
```

## Build and install

```bash
cargo build --release
cargo install --path . --force
```

Build embeds a snapshot of the nmap OS database from the paths above. At runtime, dxcan prefers the live file on disk (so upgrading nmap updates fingerprints without rebuilding).

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

## Binaries

| Binary | Role |
|--------|------|
| `dxcan` | Native scanner |
| `dxcan-nmap` | nmap XML wrapper |
| `dxcan-rustscan` | rustscan + nmap wrapper |

## Benchmarks (local checkout)

Benchmark scripts under `bench/` and docs under `references/` are kept in the working tree but are not part of the minimal git export. If you have them locally, see `references/how-to-use.md` for `bench/doc.sh`, preflight, and OpenVAS wake workflows.

# dxcan

Rust port scanner with optional service detection, role labels, and nmap-style OS fingerprinting (`--os`).

## Prerequisites

- Rust toolchain (`cargo`, edition 2021)
- Linux with raw sockets for SYN scans and `--os` (run with `sudo` or `CAP_NET_RAW`)
- **OS database file** for `--os` (see below)

## Get the OS fingerprint database

The nmap OS fingerprint database (`assets/nmap-os-db`, ~5 MB) is **not** on code branches. It lives on branch **`assets-bundle`**, which tracks **only** the `assets/` tree (orphan branch — not meant to merge into `main`).

After cloning, from your code branch (e.g. `main`):

```bash
git checkout main && git fetch origin assets-bundle && mkdir -p assets && git show origin/assets-bundle:assets/nmap-os-db > assets/nmap-os-db && git show origin/assets-bundle:assets/README.md > assets/README.md
```

Do **not** merge or pull `assets-bundle` into `main`. The one-liner above copies files locally without staging them, so you won't accidentally commit assets to `main`.

Without `assets/nmap-os-db`, `cargo build` fails on the OS module and `dxcan --os` is unavailable.

**Important:** On code branches, git does not keep these files in your working tree. After switching branches, run the one-liner again if `assets/` is missing.

## Build and install

```bash
cargo build --release
cargo install --path . --force
```

Use the built binary without installing globally:

```bash
export PATH="$PWD/target/release:$PATH"
dxcan --version
```

## Quick start

Port scan:

```bash
dxcan -H scanme.nmap.org -p 1-1024
```

Service versions:

```bash
dxcan -H scanme.nmap.org -p 22,80 --service-version
```

OS detection (requires `assets/nmap-os-db` and root):

```bash
sudo dxcan -H scanme.nmap.org -p 22,80 --os
```

Rich output (reverse DNS, versions, role labels):

```bash
dxcan -H scanme.nmap.org -p 1-1024 --rich
```

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

## Branches

| Branch | Contents |
|--------|----------|
| `main` / feature branches | Rust source, `Cargo.toml`, this README |
| `assets-bundle` | **Assets only** — `assets/nmap-os-db` + `assets/README.md` (orphan; sparse-checkout into code branches) |

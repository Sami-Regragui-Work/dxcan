use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const VHOST_CANONICAL: &str = "src/scanners/network/vhost/vhost-wordlist.txt";
const VHOST_EXTRAS: &str = include_str!("src/scanners/network/vhost/vhost-extras.txt");

fn nmap_os_db_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = env::var("DXCAN_OS_DB") {
        out.push(PathBuf::from(p));
    }
    out.push(PathBuf::from("/usr/share/nmap/nmap-os-db"));
    out.push(PathBuf::from("/usr/local/share/nmap/nmap-os-db"));
    out
}

fn nmap_vhost_base_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = env::var("DXCAN_VHOST_WORDLIST_BASE") {
        out.push(PathBuf::from(p));
    }
    out.push(PathBuf::from("/usr/share/nmap/nselib/data/vhosts-full.lst"));
    out.push(PathBuf::from("/usr/local/share/nmap/nselib/data/vhosts-full.lst"));
    out
}

fn find_nmap_os_db() -> Option<PathBuf> {
    nmap_os_db_candidates()
        .into_iter()
        .find(|p| p.is_file())
}

fn find_nmap_vhost_base() -> Option<PathBuf> {
    nmap_vhost_base_candidates()
        .into_iter()
        .find(|p| p.is_file())
}

fn merge_wordlist_fallback(base: &Path, extras: &str) -> String {
    use std::collections::BTreeSet;
    let base_raw = fs::read_to_string(base).unwrap_or_else(|e| {
        panic!(
            "failed to read vhost base {}: {e}",
            base.display()
        )
    });
    let mut entries: BTreeSet<String> = base_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect();
    entries.extend(
        extras
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_ascii_lowercase),
    );
    entries.into_iter().collect::<Vec<_>>().join("\n") + "\n"
}

fn write_vhost_wordlist(out_dir: &Path) {
    let dest = out_dir.join("vhost-wordlist.txt");
    let canonical = Path::new(VHOST_CANONICAL);
    let merged = if canonical.is_file() {
        fs::read_to_string(canonical).unwrap_or_else(|e| {
            panic!(
                "failed to read {}: {e}",
                canonical.display()
            )
        })
    } else {
        let Some(src) = find_nmap_vhost_base() else {
            panic!(
                "vhost wordlist missing. Run ./scripts/update-vhost-wordlist.sh or install nmap."
            );
        };
        eprintln!(
            "cargo:warning={} missing; merging from {}",
            VHOST_CANONICAL,
            src.display()
        );
        merge_wordlist_fallback(&src, VHOST_EXTRAS)
    };
    fs::write(&dest, &merged).unwrap_or_else(|e| {
        panic!(
            "failed to write {}: {e}",
            dest.display()
        )
    });
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        let bench_sidecar = PathBuf::from(manifest).join("target/vhost-wordlist.txt");
        if let Some(parent) = bench_sidecar.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&bench_sidecar, &merged);
    }
    println!("cargo:rerun-if-changed={VHOST_CANONICAL}");
    println!("cargo:rerun-if-changed=src/scanners/network/vhost/vhost-extras.txt");
    println!("cargo:rerun-if-changed=src/scanners/network/domain/resolvers-default.txt");
    println!("cargo:rerun-if-changed=src/scanners/network/domain/resolvers-dev.txt");
    println!("cargo:rerun-if-env-changed=DXCAN_VHOST_WORDLIST_BASE");
}

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let dest = Path::new(&out_dir).join("nmap-os-db");
    let Some(src) = find_nmap_os_db() else {
        panic!(
            "nmap-os-db not found. Install nmap (provides /usr/share/nmap/nmap-os-db) or set DXCAN_OS_DB."
        );
    };
    fs::copy(&src, &dest).unwrap_or_else(|e| {
        panic!(
            "failed to copy {} -> {}: {e}",
            src.display(),
            dest.display()
        );
    });
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=DXCAN_OS_DB");
    write_vhost_wordlist(Path::new(&out_dir));
}

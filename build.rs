use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn nmap_db_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = env::var("DXCAN_OS_DB") {
        out.push(PathBuf::from(p));
    }
    out.push(PathBuf::from("/usr/share/nmap/nmap-os-db"));
    out.push(PathBuf::from("/usr/local/share/nmap/nmap-os-db"));
    out
}

fn find_nmap_os_db() -> Option<PathBuf> {
    nmap_db_candidates()
        .into_iter()
        .find(|p| p.is_file())
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
}

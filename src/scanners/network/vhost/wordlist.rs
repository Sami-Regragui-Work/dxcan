use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const VHOST_EXTRAS: &str = include_str!("vhost-extras.txt");
const EMBEDDED_WORDLIST: &str = include_str!(concat!(env!("OUT_DIR"), "/vhost-wordlist.txt"));

pub const NMAP_VHOSTS_FULL: &str = "/usr/share/nmap/nselib/data/vhosts-full.lst";

pub fn load_wordlist(path: Option<&Path>) -> Result<Vec<String>, String> {
    let raw = match path {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("wordlist {}: {e}", p.display()))?,
        None => load_default_wordlist_raw()?,
    };
    Ok(parse_wordlist_lines(&raw))
}

pub fn expand_hostname(line: &str, base_domain: &str) -> String {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains('%') {
        return trimmed.replace("%s", base_domain);
    }
    if trimmed.contains('.') {
        return trimmed.to_string();
    }
    format!("{trimmed}.{base_domain}")
}

pub fn resolve_wordlist_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("DXCAN_VHOST_WORDLIST") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    if live_merge_enabled() {
        for candidate in [
            PathBuf::from(NMAP_VHOSTS_FULL),
            PathBuf::from("/usr/local/share/nmap/nselib/data/vhosts-full.lst"),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sidecar = dir.join("vhost-wordlist.txt");
            if sidecar.is_file() {
                return Some(sidecar);
            }
        }
    }
    let sidecar = PathBuf::from("target/vhost-wordlist.txt");
    if sidecar.is_file() {
        return Some(sidecar);
    }
    None
}

fn live_merge_enabled() -> bool {
    matches!(
        env::var("DXCAN_VHOST_LIVE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn load_default_wordlist_raw() -> Result<String, String> {
    if let Some(path) = resolve_wordlist_path() {
        if live_merge_enabled() && is_nmap_vhost_base(&path) {
            let base = fs::read_to_string(&path)
                .map_err(|e| format!("wordlist {}: {e}", path.display()))?;
            return Ok(merge_wordlist_text(&base, VHOST_EXTRAS));
        }
        return fs::read_to_string(&path)
            .map_err(|e| format!("wordlist {}: {e}", path.display()));
    }
    Ok(EMBEDDED_WORDLIST.to_string())
}

fn is_nmap_vhost_base(path: &Path) -> bool {
    path.ends_with("vhosts-full.lst")
}

fn merge_wordlist_text(base: &str, extras: &str) -> String {
    let mut entries = parse_wordlist_set(base);
    entries.extend(parse_wordlist_set(extras));
    entries.into_iter().collect::<Vec<_>>().join("\n") + "\n"
}

fn parse_wordlist_set(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn parse_wordlist_lines(raw: &str) -> Vec<String> {
    parse_wordlist_set(raw).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_prefix() {
        assert_eq!(expand_hostname("www", "example.com"), "www.example.com");
    }

    #[test]
    fn expand_percent_s() {
        assert_eq!(
            expand_hostname("www.%s", "example.com"),
            "www.example.com"
        );
    }

    #[test]
    fn fqdn_passthrough() {
        assert_eq!(
            expand_hostname("other.example.org", "example.com"),
            "other.example.org"
        );
    }

    #[test]
    fn merge_dedupes_and_sorts() {
        let merged = merge_wordlist_text("zebra\nwww\n", "api\nwww\n");
        assert_eq!(merged, "api\nwww\nzebra\n");
    }

    #[test]
    fn canonical_wordlist_nonempty() {
        let canonical = include_str!("vhost-wordlist.txt");
        let lines = parse_wordlist_lines(canonical);
        assert!(
            lines.len() > 400,
            "expected vendored merged list, got {}",
            lines.len()
        );
        assert!(lines.contains(&"www".to_string()));
        assert!(lines.contains(&"grafana".to_string()));
    }

    #[test]
    fn embedded_wordlist_nonempty() {
        let lines = parse_wordlist_lines(EMBEDDED_WORDLIST);
        assert!(
            lines.len() > 400,
            "expected embedded merged list, got {}",
            lines.len()
        );
    }

    #[test]
    fn loads_live_nmap_vhost_base_when_enabled() {
        if !live_merge_enabled() {
            return;
        }
        let Some(path) = resolve_wordlist_path() else {
            return;
        };
        if !is_nmap_vhost_base(&path) {
            return;
        }
        let raw = fs::read_to_string(&path).expect("read nmap vhosts-full");
        let lines = parse_wordlist_lines(&merge_wordlist_text(&raw, VHOST_EXTRAS));
        assert!(lines.len() > 400);
    }
}

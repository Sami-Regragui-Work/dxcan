use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_WORDLIST: &str = include_str!("vhost-smoke.txt");
const EMBEDDED_WORDLIST: &str = include_str!(concat!(env!("OUT_DIR"), "/vhost-wordlist.txt"));

pub fn load_wordlist(path: Option<&Path>, dev: bool) -> Result<Vec<String>, String> {
    let raw = match path {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("wordlist {}: {e}", p.display()))?,
        None if dev => DEV_WORDLIST.to_string(),
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

fn load_default_wordlist_raw() -> Result<String, String> {
    if let Some(path) = resolve_wordlist_path() {
        return fs::read_to_string(&path)
            .map_err(|e| format!("wordlist {}: {e}", path.display()));
    }
    Ok(EMBEDDED_WORDLIST.to_string())
}

fn parse_wordlist_set(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
}

pub fn parse_wordlist_lines(raw: &str) -> Vec<String> {
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
        let mut entries = parse_wordlist_set("zebra\nwww\n");
        entries.extend(parse_wordlist_set("api\nwww\n"));
        let merged = entries.into_iter().collect::<Vec<_>>().join("\n") + "\n";
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
    fn dev_wordlist_nonempty() {
        let lines = parse_wordlist_lines(DEV_WORDLIST);
        assert!(lines.len() >= 8);
    }
}

use std::fs;
use std::path::Path;

const DEFAULT_WORDLIST: &str = include_str!("../../../../assets/wordlists/vhost-small.txt");

pub fn load_wordlist(path: Option<&Path>) -> Result<Vec<String>, String> {
    let raw = match path {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("wordlist {}: {e}", p.display()))?,
        None => DEFAULT_WORDLIST.to_string(),
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

fn parse_wordlist_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
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
}

use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const EMBEDDED_PRODUCTION: &str = include_str!("resolvers-default.txt");
const EMBEDDED_DEV: &str = include_str!("resolvers-dev.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSource {
    Explicit(PathBuf),
    Environment(PathBuf),
    DevEmbedded,
    Embedded,
}

impl ResolverSource {
    pub fn label(&self) -> String {
        match self {
            Self::Explicit(p) => format!("--domain-resolvers {}", p.display()),
            Self::Environment(p) => format!("DXCAN_DOMAIN_RESOLVERS={}", p.display()),
            Self::DevEmbedded => "dev resolvers-dev.txt".into(),
            Self::Embedded => "embedded resolvers-default.txt".into(),
        }
    }
}

fn load_ips_from_file(path: &Path) -> Result<Vec<IpAddr>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("resolvers {}: {e}", path.display()))?;
    let ips = parse_resolver_lines(&raw);
    if ips.is_empty() {
        return Err(format!("no resolvers in {}", path.display()));
    }
    Ok(ips)
}

pub fn resolve_resolver_source(explicit: Option<&Path>, dev: bool) -> Result<ResolverSource, String> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(format!("resolvers file not found: {}", path.display()));
        }
        return Ok(ResolverSource::Explicit(path.to_path_buf()));
    }
    if let Ok(env_path) = env::var("DXCAN_DOMAIN_RESOLVERS") {
        let path = PathBuf::from(&env_path);
        if !path.is_file() {
            return Err(format!(
                "DXCAN_DOMAIN_RESOLVERS file not found: {}",
                path.display()
            ));
        }
        return Ok(ResolverSource::Environment(path));
    }
    if dev {
        return Ok(ResolverSource::DevEmbedded);
    }
    Ok(ResolverSource::Embedded)
}

pub fn load_resolver_ips(
    explicit: Option<&Path>,
    dev: bool,
) -> Result<(Vec<IpAddr>, ResolverSource), String> {
    let source = resolve_resolver_source(explicit, dev)?;
    let ips = match &source {
        ResolverSource::Embedded => parse_resolver_lines(EMBEDDED_PRODUCTION),
        ResolverSource::DevEmbedded => parse_resolver_lines(EMBEDDED_DEV),
        ResolverSource::Explicit(path) | ResolverSource::Environment(path) => {
            load_ips_from_file(path)?
        }
    };
    if ips.is_empty() {
        return Err("no DNS resolvers configured".into());
    }
    Ok((ips, source))
}

pub fn parse_resolver_lines(raw: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let token = trimmed.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = token.parse::<IpAddr>() {
            ips.push(ip);
        }
    }
    ips.sort_unstable();
    ips.dedup();
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolver_file_lines() {
        let raw = "8.8.8.8\n# comment\n1.1.1.1\n";
        let ips = parse_resolver_lines(raw);
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn embedded_default_nonempty() {
        let ips = parse_resolver_lines(EMBEDDED_PRODUCTION);
        assert!(ips.len() >= 4);
    }

    #[test]
    fn dev_source_when_dev_flag() {
        env::remove_var("DXCAN_DOMAIN_RESOLVERS");
        let source = resolve_resolver_source(None, true).expect("source");
        assert_eq!(source, ResolverSource::DevEmbedded);
    }

    #[test]
    fn production_source_without_dev() {
        env::remove_var("DXCAN_DOMAIN_RESOLVERS");
        let source = resolve_resolver_source(None, false).expect("source");
        assert_eq!(source, ResolverSource::Embedded);
    }
}

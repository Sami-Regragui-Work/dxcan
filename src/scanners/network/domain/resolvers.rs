use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const EMBEDDED_FALLBACK: &str = include_str!("resolvers-extras.txt");
const EMBEDDED_DEV: &str = include_str!("resolvers-dev.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSource {
    Explicit(PathBuf),
    Environment(PathBuf),
    DevEmbedded,
    Vendored(PathBuf),
    FallbackEmbedded,
}

impl ResolverSource {
    pub fn label(&self) -> String {
        match self {
            Self::Explicit(p) => format!("--domain-resolvers {}", p.display()),
            Self::Environment(p) => format!("DXCAN_DOMAIN_RESOLVERS={}", p.display()),
            Self::DevEmbedded => "dev resolvers-dev.txt".into(),
            Self::Vendored(p) => format!("vendored {}", p.display()),
            Self::FallbackEmbedded => "embedded resolvers-extras.txt".into(),
        }
    }
}

pub fn resolve_production_resolvers_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("DXCAN_DOMAIN_RESOLVERS_DEFAULT") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["resolvers-default.txt", "resolvers.txt"] {
                let path = dir.join(name);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    for candidate in [
        PathBuf::from("target/resolvers-trusted.txt"),
        PathBuf::from("target/resolvers.txt"),
        PathBuf::from("src/scanners/network/domain/resolvers-trusted.txt"),
        PathBuf::from("src/scanners/network/domain/resolvers-default.txt"),
    ] {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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
    if let Some(path) = resolve_production_resolvers_path() {
        return Ok(ResolverSource::Vendored(path));
    }
    Ok(ResolverSource::FallbackEmbedded)
}

pub fn load_resolver_ips(
    explicit: Option<&Path>,
    dev: bool,
) -> Result<(Vec<IpAddr>, ResolverSource), String> {
    let source = resolve_resolver_source(explicit, dev)?;
    let ips = match &source {
        ResolverSource::FallbackEmbedded => parse_resolver_lines(EMBEDDED_FALLBACK),
        ResolverSource::DevEmbedded => parse_resolver_lines(EMBEDDED_DEV),
        ResolverSource::Explicit(path)
        | ResolverSource::Environment(path)
        | ResolverSource::Vendored(path) => load_ips_from_file(path)?,
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

pub fn compute_max_inflight(
    workers: usize,
    resolver_count: usize,
    override_limit: Option<usize>,
) -> usize {
    if let Some(limit) = override_limit {
        return limit.max(1);
    }
    workers
        .min(resolver_count.saturating_mul(4))
        .clamp(32, 128)
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
    fn fallback_embedded_nonempty() {
        let ips = parse_resolver_lines(EMBEDDED_FALLBACK);
        assert!(ips.len() >= 4);
    }

    #[test]
    fn dev_source_when_dev_flag() {
        env::remove_var("DXCAN_DOMAIN_RESOLVERS");
        let source = resolve_resolver_source(None, true).expect("source");
        assert_eq!(source, ResolverSource::DevEmbedded);
    }

    #[test]
    fn production_prefers_vendored_file() {
        env::remove_var("DXCAN_DOMAIN_RESOLVERS");
        let source = resolve_resolver_source(None, false).expect("source");
        assert!(matches!(
            source,
            ResolverSource::Vendored(_) | ResolverSource::FallbackEmbedded
        ));
    }

    #[test]
    fn inflight_scales_with_pool() {
        assert_eq!(compute_max_inflight(100, 8, None), 32);
        assert_eq!(compute_max_inflight(100, 200, None), 100);
        assert_eq!(compute_max_inflight(100, 200, Some(64)), 64);
    }
}

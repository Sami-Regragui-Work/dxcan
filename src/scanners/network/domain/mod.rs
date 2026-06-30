use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

mod dns;
mod resolvers;
mod udp;
mod wildcard;
mod wordlist;

pub use wordlist::{expand_hostname, load_wordlist};
use dns::{build_client, format_ip, DnsAnswer, DnsClient};
use resolvers::load_resolver_ips;
use wildcard::{detect_wildcard_ips, is_wildcard_hit, random_label};

#[derive(Debug, Clone)]
pub struct DomainOptions {
    pub apex: String,
    pub wordlist_path: Option<PathBuf>,
    pub resolvers_path: Option<PathBuf>,
    pub workers: usize,
    pub query_timeout: Duration,
    pub wildcard_samples: u32,
    pub filter_wildcard: bool,
    pub query_aaaa: bool,
    pub show_cname: bool,
    pub show_ttl: bool,
    pub dev: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainHit {
    pub fqdn: String,
    pub ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aaaa: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct DomainDiscoverResult {
    pub hits: Vec<DomainHit>,
    pub probed: usize,
    pub wildcard_ips: Vec<String>,
    pub detection_ms: f64,
    pub resolver_source: String,
}

pub fn normalize_apex(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

fn answer_to_hit(fqdn: String, answer: &DnsAnswer, latency_ms: f64, opts: &DomainOptions) -> DomainHit {
    DomainHit {
        fqdn,
        ips: answer.a.iter().map(|ip| format_ip(*ip)).collect(),
        aaaa: if opts.query_aaaa {
            answer.aaaa.iter().map(|ip| format_ip(*ip)).collect()
        } else {
            Vec::new()
        },
        cname: if opts.show_cname {
            answer.cname.clone()
        } else {
            None
        },
        ttl: if opts.show_ttl { answer.ttl } else { None },
        latency_ms,
    }
}

async fn lookup_one(
    client: Arc<DnsClient>,
    fqdn: String,
    query_aaaa: bool,
) -> (String, Result<DnsAnswer, String>, f64) {
    let t0 = Instant::now();
    let result = client.lookup(&fqdn, true, query_aaaa).await;
    (fqdn, result, t0.elapsed().as_secs_f64() * 1000.0)
}

pub async fn discover_domains(opts: &DomainOptions) -> Result<DomainDiscoverResult, String> {
    let start = Instant::now();
    let apex = normalize_apex(&opts.apex);
    if apex.is_empty() {
        return Err("apex domain is empty".into());
    }
    if !apex.contains('.') {
        return Err(format!("invalid apex domain: {apex}"));
    }

    let lines = load_wordlist(opts.wordlist_path.as_deref(), opts.dev)?;
    if lines.is_empty() {
        return Err("wordlist is empty".into());
    }

    let fqdns: Vec<String> = lines
        .iter()
        .map(|l| expand_hostname(l, &apex))
        .filter(|h| !h.is_empty() && h != &apex)
        .collect();

    let (resolver_ips, resolver_source) =
        load_resolver_ips(opts.resolvers_path.as_deref(), opts.dev)?;
    let rich = opts.query_aaaa || opts.show_cname || opts.show_ttl;
    let max_inflight = opts
        .workers
        .min(resolver_ips.len().saturating_mul(8))
        .clamp(24, 72);
    let client = Arc::new(
        build_client(
            &resolver_ips,
            opts.query_timeout,
            rich,
            max_inflight,
        )
        .await?,
    );

    let wildcard_set = if opts.filter_wildcard {
        detect_wildcard_ips(
            &client,
            &apex,
            opts.wildcard_samples,
            start,
            opts.query_aaaa,
        )
        .await
    } else {
        BTreeSet::new()
    };

    let sem = Arc::new(Semaphore::new(opts.workers.max(1)));
    let mut futs = FuturesUnordered::new();
    for fqdn in fqdns {
        let sem = sem.clone();
        let client = client.clone();
        let query_aaaa = opts.query_aaaa;
        futs.push(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            lookup_one(client, fqdn, query_aaaa).await
        });
    }

    let mut hits = Vec::new();
    let mut probed = 0usize;
    while let Some((fqdn, result, latency_ms)) = futs.next().await {
        probed += 1;
        let Ok(answer) = result else { continue };
        if opts.filter_wildcard && is_wildcard_hit(&answer.wildcard_ips(), &wildcard_set) {
            continue;
        }
        hits.push(answer_to_hit(fqdn, &answer, latency_ms, opts));
    }

    hits.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));

    Ok(DomainDiscoverResult {
        hits,
        probed,
        wildcard_ips: wildcard_set.iter().map(|ip| format_ip(*ip)).collect(),
        detection_ms: start.elapsed().as_secs_f64() * 1000.0,
        resolver_source: resolver_source.label(),
    })
}

pub async fn probe_random_label(
    client: &DnsClient,
    apex: &str,
    seed: u128,
    query_aaaa: bool,
) -> Option<BTreeSet<IpAddr>> {
    let fqdn = format!("{}.{}", random_label(seed), apex);
    let Ok(answer) = client.lookup(&fqdn, true, query_aaaa).await else {
        return None;
    };
    let ips = answer.wildcard_ips();
    if ips.is_empty() {
        None
    } else {
        Some(ips.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_trailing_dot() {
        assert_eq!(normalize_apex("Example.COM."), "example.com");
    }
}

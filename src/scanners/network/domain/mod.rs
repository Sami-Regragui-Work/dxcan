use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{watch, Semaphore};

mod dns;
mod resolvers;
mod udp;
mod wildcard;
mod wordlist;

pub use wordlist::{expand_hostname, load_wordlist};
use dns::{build_client, format_ip, DnsAnswer, DnsClient};
use resolvers::{compute_max_inflight, load_resolver_ips};
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
    pub max_inflight: Option<usize>,
    pub max_retries: u8,
    pub resolver_limit: Option<usize>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DomainProbeStats {
    pub probed: usize,
    pub hits: usize,
    pub nxdomain: usize,
    pub timeout: usize,
    pub errors: usize,
    pub wildcard_filtered: usize,
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
    pub stats: DomainProbeStats,
}

fn classify_lookup_error(err: &str) -> &'static str {
    if err.ends_with(": nxdomain") || err.contains(": nxdomain") {
        "nxdomain"
    } else if err.ends_with(": timeout") {
        "timeout"
    } else {
        "error"
    }
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

    let (mut resolver_ips, resolver_source) =
        load_resolver_ips(opts.resolvers_path.as_deref(), opts.dev)?;
    if let Some(limit) = opts.resolver_limit {
        if limit > 0 && resolver_ips.len() > limit {
            resolver_ips.truncate(limit);
        }
    }
    let rich = opts.query_aaaa || opts.show_cname || opts.show_ttl;
    let max_inflight = compute_max_inflight(
        opts.workers,
        resolver_ips.len(),
        opts.max_inflight,
    );
    let client = Arc::new(
        build_client(
            &resolver_ips,
            opts.query_timeout,
            rich,
            max_inflight,
            opts.max_retries,
        )
        .await?,
    );

    let wildcard_watch = if opts.filter_wildcard {
        let (tx, rx) = watch::channel(None::<BTreeSet<IpAddr>>);
        let client_w = client.clone();
        let apex_w = apex.clone();
        let samples = opts.wildcard_samples;
        let query_aaaa = opts.query_aaaa;
        tokio::spawn(async move {
            let set = detect_wildcard_ips(&client_w, &apex_w, samples, start, query_aaaa).await;
            let _ = tx.send(Some(set));
        });
        Some(rx)
    } else {
        None
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
    let mut stats = DomainProbeStats::default();
    while let Some((fqdn, result, latency_ms)) = futs.next().await {
        stats.probed += 1;
        let Ok(answer) = result else {
            match result {
                Err(ref e) => match classify_lookup_error(e) {
                    "nxdomain" => stats.nxdomain += 1,
                    "timeout" => stats.timeout += 1,
                    _ => stats.errors += 1,
                },
                _ => {}
            }
            continue;
        };
        if opts.filter_wildcard {
            if let Some(ref rx) = wildcard_watch {
                if let Some(ref set) = *rx.borrow() {
                    if is_wildcard_hit(&answer.wildcard_ips(), set) {
                        stats.wildcard_filtered += 1;
                        continue;
                    }
                }
            }
        }
        stats.hits += 1;
        hits.push(answer_to_hit(fqdn, &answer, latency_ms, opts));
    }

    hits.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));

    let wildcard_set = if let Some(rx) = wildcard_watch {
        let mut guard = rx.clone();
        while guard.borrow().is_none() {
            if guard.changed().await.is_err() {
                break;
            }
        }
        let set = guard.borrow().clone().unwrap_or_default();
        set
    } else {
        BTreeSet::new()
    };

    Ok(DomainDiscoverResult {
        hits,
        probed: stats.probed,
        wildcard_ips: wildcard_set.iter().map(|ip| format_ip(*ip)).collect(),
        detection_ms: start.elapsed().as_secs_f64() * 1000.0,
        resolver_source: resolver_source.label(),
        stats,
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

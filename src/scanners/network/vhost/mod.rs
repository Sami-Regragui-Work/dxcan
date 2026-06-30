use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

mod diff;
mod probe;
pub mod wordlist;

use diff::{catchall_consensus, is_actionable_hit, length_only_diff};
pub use probe::{body_hash_hex, is_http_port, port_uses_tls};
use probe::{probe_host, HttpResponse};
use wordlist::{expand_hostname, load_wordlist};

#[derive(Debug, Clone)]
pub struct VhostOptions {
    pub ip: IpAddr,
    pub port: u16,
    pub base_domain: String,
    pub wordlist_path: Option<PathBuf>,
    pub path: String,
    pub workers: usize,
    pub request_timeout: Duration,
    pub calibrate: u32,
    pub tls: Option<bool>,
    pub match_hash: bool,
    pub length_margin: usize,
    pub ignore_lengths: Vec<usize>,
    pub ignore_statuses: Vec<u16>,
    pub dev: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VhostHit {
    pub hostname: String,
    pub port: u16,
    pub status: u16,
    pub body_len: usize,
    pub body_lines: usize,
    pub body_words: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub body_hash: String,
    pub latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct VhostDiscoverResult {
    pub hits: Vec<VhostHit>,
    pub probed: usize,
    pub baseline: HttpResponse,
    pub detection_ms: f64,
    pub port: u16,
    pub tls: bool,
}

pub fn pick_http_ports(open_ports: &[u16], explicit: Option<u16>) -> Vec<u16> {
    if let Some(p) = explicit {
        return vec![p];
    }
    let mut ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| is_http_port(*p))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn parse_usize_list(raw: &str) -> Vec<usize> {
    raw.split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect()
}

pub fn parse_status_list(raw: &str) -> Vec<u16> {
    raw.split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect()
}

pub async fn discover_vhosts(opts: &VhostOptions) -> Result<VhostDiscoverResult, String> {
    let start = Instant::now();
    let lines = load_wordlist(opts.wordlist_path.as_deref(), opts.dev)?;
    if lines.is_empty() {
        return Err("wordlist is empty".into());
    }

    let hostnames: Vec<String> = lines
        .iter()
        .map(|l| expand_hostname(l, &opts.base_domain))
        .filter(|h| !h.is_empty())
        .collect();

    let use_tls = opts.tls.unwrap_or_else(|| port_uses_tls(opts.port));
    let calibrate = opts.calibrate.max(1);

    let mut cal_futs = FuturesUnordered::new();
    for i in 0..calibrate {
        let baseline_host = format!(
            "invalid-{i}-{:x}.invalid",
            start.elapsed().as_nanos() & 0xffff_ffff
        );
        let ip = opts.ip;
        let port = opts.port;
        let path = opts.path.clone();
        let request_timeout = opts.request_timeout;
        cal_futs.push(async move {
            probe_host(ip, port, &baseline_host, &path, use_tls, request_timeout).await
        });
    }
    let mut baselines = Vec::new();
    while let Some(result) = cal_futs.next().await {
        baselines.push(result?);
    }

    let mut probed = 0usize;
    let mut candidates: Vec<(String, HttpResponse)> = Vec::new();

    if use_tls {
        let sem = Arc::new(Semaphore::new(opts.workers.max(1)));
        let mut futs = FuturesUnordered::new();
        for hostname in hostnames.clone() {
            let sem = sem.clone();
            let ip = opts.ip;
            let port = opts.port;
            let path = opts.path.clone();
            let request_timeout = opts.request_timeout;
            futs.push(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let resp = probe_host(ip, port, &hostname, &path, use_tls, request_timeout).await;
                (hostname, resp)
            });
        }
        while let Some((hostname, resp)) = futs.next().await {
            probed += 1;
            let Ok(resp) = resp else { continue };
            candidates.push((hostname, resp));
        }
    } else {
        probed = hostnames.len();
        let pooled = probe::probe_plain_pooled(
            opts.ip,
            opts.port,
            hostnames,
            &opts.path,
            opts.workers,
            opts.request_timeout,
        )
        .await;
        for (hostname, resp) in pooled {
            let Ok(resp) = resp else { continue };
            candidates.push((hostname, resp));
        }
    }

    let candidate_responses: Vec<HttpResponse> =
        candidates.iter().map(|(_, r)| r.clone()).collect();
    let catchall = if candidate_responses.is_empty() {
        catchall_consensus(&baselines)
    } else {
        catchall_consensus(&candidate_responses)
    };
    let mut ignore_lengths = opts.ignore_lengths.clone();
    if !ignore_lengths.contains(&catchall.body_len) {
        ignore_lengths.push(catchall.body_len);
    }

    let outlier_count = candidates
        .iter()
        .filter(|(_, r)| length_only_diff(r, &catchall, opts.length_margin))
        .count();
    let verify_length_outliers = !opts.match_hash && outlier_count > 0 && outlier_count <= 10;

    let mut hits = Vec::new();
    for (hostname, resp) in candidates {
        let mut resp = resp;
        if verify_length_outliers && length_only_diff(&resp, &catchall, opts.length_margin) {
            if let Ok(verify) = probe_host(
                opts.ip,
                opts.port,
                &hostname,
                &opts.path,
                use_tls,
                opts.request_timeout,
            )
            .await
            {
                resp = verify;
            }
        }
        if is_actionable_hit(
            &resp,
            &catchall,
            opts.match_hash,
            opts.length_margin,
            &ignore_lengths,
            &opts.ignore_statuses,
        ) {
            hits.push(VhostHit {
                hostname,
                port: opts.port,
                status: resp.status,
                body_len: resp.body_len,
                body_lines: resp.body_lines,
                body_words: resp.body_words,
                location: resp.location.clone(),
                body_hash: probe::body_hash_hex(resp.body_hash),
                latency_ms: resp.latency_ms,
            });
        }
    }

    hits.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    Ok(VhostDiscoverResult {
        hits,
        probed,
        baseline: catchall,
        detection_ms: start.elapsed().as_secs_f64() * 1000.0,
        port: opts.port,
        tls: use_tls,
    })
}

pub fn resolve_base_domain(host_arg: &str, reverse_dns: Option<&str>) -> String {
    if host_arg.chars().any(|c| c.is_ascii_alphabetic()) && !host_arg.parse::<IpAddr>().is_ok() {
        return host_arg.to_string();
    }
    if let Some(name) = reverse_dns {
        return name.to_string();
    }
    host_arg.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_ports_from_open() {
        let open = vec![22, 80, 443, 3306];
        assert_eq!(pick_http_ports(&open, None), vec![80, 443]);
    }

    #[test]
    fn explicit_port_wins() {
        assert_eq!(pick_http_ports(&[80], Some(8080)), vec![8080]);
    }

    #[test]
    fn parse_lists() {
        assert_eq!(parse_usize_list("100,200"), vec![100, 200]);
        assert_eq!(parse_status_list("404,400"), vec![404, 400]);
    }
}

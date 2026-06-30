use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};

use super::dns::DnsClient;
use super::probe_random_label;

pub fn random_label(seed: u128) -> String {
    format!("dxcan-nx-{:012x}", seed & 0xffff_ffff_ffff)
}

pub async fn detect_wildcard_ips(
    client: &DnsClient,
    apex: &str,
    samples: u32,
    start: Instant,
    query_aaaa: bool,
) -> BTreeSet<IpAddr> {
    let n = samples.max(1);
    let mut futs = FuturesUnordered::new();
    for i in 0..n {
        let seed = start.elapsed().as_nanos() ^ ((i as u128) << 48);
        futs.push(probe_random_label(client, apex, seed, query_aaaa));
    }
    let mut resolved_sets: Vec<BTreeSet<IpAddr>> = Vec::new();
    while let Some(set) = futs.next().await {
        if let Some(set) = set {
            resolved_sets.push(set);
        }
    }
    if resolved_sets.len() < 2 {
        return BTreeSet::new();
    }
    let first = &resolved_sets[0];
    if resolved_sets.iter().all(|s| s == first) {
        first.clone()
    } else {
        BTreeSet::new()
    }
}

pub fn is_wildcard_hit(ips: &[IpAddr], wildcard: &BTreeSet<IpAddr>) -> bool {
    if wildcard.is_empty() || ips.is_empty() {
        return false;
    }
    ips.iter().all(|ip| wildcard.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_hit_when_all_ips_match() {
        let w: BTreeSet<IpAddr> = ["1.2.3.4".parse().unwrap()].into_iter().collect();
        let ips = vec!["1.2.3.4".parse().unwrap()];
        assert!(is_wildcard_hit(&ips, &w));
    }

    #[test]
    fn not_wildcard_when_extra_ip() {
        let w: BTreeSet<IpAddr> = ["1.2.3.4".parse().unwrap()].into_iter().collect();
        let ips = vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()];
        assert!(!is_wildcard_hit(&ips, &w));
    }
}

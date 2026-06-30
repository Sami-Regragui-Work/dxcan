use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts, ServerGroup};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

#[derive(Debug, Clone, Default)]
pub struct DnsAnswer {
    pub a: Vec<IpAddr>,
    pub aaaa: Vec<IpAddr>,
    pub cname: Option<String>,
    pub ttl: Option<u32>,
}

impl DnsAnswer {
    pub fn has_records(&self) -> bool {
        !self.a.is_empty() || !self.aaaa.is_empty() || self.cname.is_some()
    }

    pub fn wildcard_ips(&self) -> Vec<IpAddr> {
        let mut ips = self.a.clone();
        ips.extend(self.aaaa.iter().copied());
        ips.sort_unstable();
        ips.dedup();
        ips
    }
}

pub struct HickoryDnsClient {
    resolver: TokioResolver,
}

pub enum DnsClient {
    Udp(Arc<super::udp::UdpDnsClient>),
    Hickory(HickoryDnsClient),
}

fn fqdn_query(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.');
    format!("{trimmed}.")
}

pub fn build_hickory_client(ips: &[IpAddr], query_timeout: Duration) -> Result<HickoryDnsClient, String> {
    if ips.is_empty() {
        return Err("no DNS resolvers configured".into());
    }
    let group = ServerGroup {
        ips,
        server_name: "dns",
        path: "/dns-query",
    };
    let name_servers: Vec<_> = group.udp().collect();
    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = query_timeout;
    opts.attempts = 1;
    opts.num_concurrent_reqs = 200;
    opts.cache_size = 0;
    opts.edns0 = true;
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| format!("dns resolver: {e}"))?;
    Ok(HickoryDnsClient { resolver })
}

fn ingest_record(answer: &mut DnsAnswer, record: &hickory_resolver::proto::rr::Record) {
    match &record.data {
        RData::A(ip) => answer.a.push(IpAddr::V4(ip.0)),
        RData::AAAA(ip) => answer.aaaa.push(IpAddr::V6(ip.0)),
        RData::CNAME(cname) => {
            if answer.cname.is_none() {
                answer.cname = Some(cname.to_utf8());
            }
        }
        _ => {}
    }
    if answer.ttl.is_none() {
        answer.ttl = Some(record.ttl);
    }
}

impl HickoryDnsClient {
    pub async fn lookup(
        &self,
        fqdn: &str,
        query_a: bool,
        query_aaaa: bool,
    ) -> Result<DnsAnswer, String> {
        let name = fqdn_query(fqdn);
        let mut answer = DnsAnswer::default();
        if query_a || (!query_a && !query_aaaa) {
            if let Ok(response) = self.resolver.lookup(name.clone(), RecordType::A).await {
                for record in response.answers() {
                    ingest_record(&mut answer, record);
                }
            }
        }
        if query_aaaa {
            if let Ok(response) = self.resolver.lookup(name, RecordType::AAAA).await {
                for record in response.answers() {
                    ingest_record(&mut answer, record);
                }
            }
        }
        answer.a.sort_unstable();
        answer.a.dedup();
        answer.aaaa.sort_unstable();
        answer.aaaa.dedup();
        if answer.has_records() {
            Ok(answer)
        } else {
            Err(format!("{fqdn}: nxdomain"))
        }
    }
}

impl DnsClient {
    pub async fn lookup(
        &self,
        fqdn: &str,
        query_a: bool,
        query_aaaa: bool,
    ) -> Result<DnsAnswer, String> {
        match self {
            DnsClient::Udp(client) => client.lookup_a(fqdn).await,
            DnsClient::Hickory(client) => client.lookup(fqdn, query_a, query_aaaa).await,
        }
    }
}

pub async fn build_client(
    ips: &[IpAddr],
    query_timeout: Duration,
    rich: bool,
) -> Result<DnsClient, String> {
    if rich {
        Ok(DnsClient::Hickory(build_hickory_client(ips, query_timeout)?))
    } else {
        Ok(DnsClient::Udp(
            super::udp::build_udp_client(ips, query_timeout).await?,
        ))
    }
}

pub fn format_ip(ip: IpAddr) -> String {
    ip.to_string()
}

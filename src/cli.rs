use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ScanMethod {
    Auto,
    Connect,
    Syn,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScanMode {
    OpenOnly,
    Full,
}

#[derive(Parser)]
#[command(
    name = "dxcan",
    about = "Lightweight TCP port scanner — part of the DXC platform.",
    version
)]
pub struct Args {
    #[arg(short = 'H', long)]
    pub host: String,

    #[arg(short, long)]
    pub ports: String,

    #[arg(short, long, default_value_t = 0.5)]
    pub timeout: f64,

    #[arg(short, long, default_value_t = 500)]
    pub workers: usize,

    #[arg(long = "scan-method", value_enum, default_value_t = ScanMethod::Auto)]
    pub scan_method: ScanMethod,

    #[arg(long)]
    pub verify: bool,

    #[arg(long = "service-version", short = 's', alias = "sv")]
    pub service_version: bool,

    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    #[arg(long = "role-labels")]
    pub role_labels: bool,

    #[arg(long = "os", short = 'O')]
    pub os_detect: bool,

    #[arg(long = "product-hints")]
    pub product_hints: bool,

    #[arg(long = "os-rich")]
    pub os_rich: bool,

    #[arg(long = "sv-rich")]
    pub sv_rich: bool,

    #[arg(long = "vhost")]
    pub vhost: bool,

    #[arg(long = "vhost-wordlist")]
    pub vhost_wordlist: Option<String>,

    #[arg(long = "vhost-port")]
    pub vhost_port: Option<u16>,

    #[arg(long = "vhost-domain")]
    pub vhost_domain: Option<String>,

    #[arg(long = "vhost-workers")]
    pub vhost_workers: Option<usize>,

    #[arg(long = "vhost-path", default_value = "/")]
    pub vhost_path: String,

    #[arg(long = "vhost-calibrate", default_value_t = 3)]
    pub vhost_calibrate: u32,

    #[arg(long = "vhost-hash")]
    pub vhost_hash: bool,

    #[arg(long = "vhost-ignore-length")]
    pub vhost_ignore_length: Option<String>,

    #[arg(long = "vhost-ignore-status")]
    pub vhost_ignore_status: Option<String>,

    #[arg(long = "vhost-length-margin", default_value_t = 0)]
    pub vhost_length_margin: usize,

    #[arg(
        long = "vhost-tls",
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    pub vhost_tls: Option<bool>,

    #[arg(long = "domain")]
    pub domain: bool,

    #[arg(long = "domain-wordlist")]
    pub domain_wordlist: Option<String>,

    #[arg(long = "domain-workers")]
    pub domain_workers: Option<usize>,

    #[arg(long = "domain-wildcard-samples", default_value_t = 3)]
    pub domain_wildcard_samples: u32,

    #[arg(long = "domain-no-wildcard-filter")]
    pub domain_no_wildcard_filter: bool,

    #[arg(long = "domain-resolvers")]
    pub domain_resolvers: Option<String>,

    #[arg(long = "domain-query-timeout")]
    pub domain_query_timeout: Option<f64>,

    #[arg(long = "domain-aaaa")]
    pub domain_aaaa: bool,

    #[arg(long = "domain-rich")]
    pub domain_rich: bool,

    #[arg(long = "domain-max-inflight")]
    pub domain_max_inflight: Option<usize>,

    #[arg(long, help = "Smoke wordlists and dev resolver lists for local testing")]
    pub dev: bool,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long)]
    pub precise: bool,

    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub debug: bool,
}

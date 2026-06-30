use serde::Serialize;

#[derive(Serialize)]
pub struct PortEntry {
    pub port:       u16,
    pub protocol:   String,
    pub state:      String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:      Option<String>,
}

#[derive(Serialize, Clone)]
pub struct VhostEntry {
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

#[derive(Serialize, Clone)]
pub struct DomainEntry {
    pub fqdn: String,
    pub ips: Vec<String>,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aaaa: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize)]
pub struct ScanOutput {
    pub tool:       String,
    pub host:       String,
    pub ip:         String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<String>,
    pub elapsed_ms: f64,
    pub scanned:    usize,
    pub shown:      usize,
    pub results:    Vec<PortEntry>,
    pub info_level: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_guess:   Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_accuracy: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_gen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_running: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub os_cpes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vhosts: Vec<VhostEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_probed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_elapsed_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_baseline_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_baseline_lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_baseline_words: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_probed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_elapsed_ms: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_wildcard_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_resolver_source: Option<String>,
}
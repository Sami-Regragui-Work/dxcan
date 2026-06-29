//! Stage 2 — Service / banner detection
//!
//! Three-layer detection per open port:
//!   1. Passive grab  — wait for server to speak first
//!   2. Active probe  — send a targeted probe, read response
//!   3. Port fallback — label by well-known port number
//!
//! Produces a ServiceResult per port, to be merged with PortResult
//! from the port scanner stage.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Confidence {
    /// Banner matched a known pattern — high trust
    Confirmed,
    /// Active probe got a recognisable response — medium trust
    Heuristic,
    /// Only the port number was used — low trust
    PortGuess,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "confirmed"),
            Confidence::Heuristic => write!(f, "heuristic"),
            Confidence::PortGuess => write!(f, "port-guess"),
        }
    }
}

impl serde::Serialize for Confidence {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceResult {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner_raw: Option<String>,
    pub confidence: Confidence,
    /// Total time spent in service detection for this port (ms)
    pub detection_ms: f64,
}

// ---------------------------------------------------------------------------
// Prober
// ---------------------------------------------------------------------------

pub struct ServiceProber {
    passive_timeout: Duration,
    active_timeout: Duration,
}

impl ServiceProber {
    /// passive_ms — how long to wait for a server-first banner
    /// active_ms  — how long to wait after sending a probe
    pub fn new(passive_ms: u64, active_ms: u64) -> Self {
        Self {
            passive_timeout: Duration::from_millis(passive_ms),
            active_timeout: Duration::from_millis(active_ms),
        }
    }

    /// Probe a single open port. Returns a ServiceResult.
    pub async fn probe(&self, ip: IpAddr, port: u16) -> ServiceResult {
        let start = Instant::now();
        let addr = SocketAddr::new(ip, port);

        // --- connect ---
        let stream = match timeout(self.active_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                return self.port_fallback(port, start.elapsed().as_secs_f64() * 1000.0);
            }
        };

        // --- layer 1: passive grab ---
        if let Some(mut result) = self.passive_grab(&stream, port).await {
            result.detection_ms = start.elapsed().as_secs_f64() * 1000.0;
            return result;
        }

        // --- layer 2: active probe ---
        if let Some(mut result) = self.active_probe(stream, port).await {
            result.detection_ms = start.elapsed().as_secs_f64() * 1000.0;
            return result;
        }

        // --- layer 3: port fallback ---
        self.port_fallback(port, start.elapsed().as_secs_f64() * 1000.0)
    }

    // -----------------------------------------------------------------------
    // Layer 1 — passive grab
    // -----------------------------------------------------------------------

    async fn passive_grab(&self, stream: &TcpStream, port: u16) -> Option<ServiceResult> {
        let mut buf = vec![0u8; 1024];
        let n = match timeout(self.passive_timeout, async {
            let mut readable = stream.readable();
            loop {
                readable.await.ok()?;
                match stream.try_read(&mut buf) {
                    Ok(0) => return None,
                    Ok(n) => return Some(n),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        readable = stream.readable();
                        continue;
                    }
                    Err(_) => return None,
                }
            }
        })
        .await
        {
            Ok(Some(n)) => n,
            _ => return None,
        };

        let banner = &buf[..n];
        // detection_ms filled in by caller
        match_banner(banner, port, Confidence::Confirmed)
    }

    // -----------------------------------------------------------------------
    // Layer 2 — active probe
    // -----------------------------------------------------------------------

    async fn active_probe(&self, mut stream: TcpStream, port: u16) -> Option<ServiceResult> {
        let probe = active_probe_bytes(port)?;

        if timeout(self.active_timeout, stream.write_all(probe))
            .await
            .is_err()
        {
            return None;
        }

        let mut buf = vec![0u8; 1024];
        let n = match timeout(self.active_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };

        let banner = &buf[..n];
        // detection_ms filled in by caller
        match_banner(banner, port, Confidence::Heuristic)
    }

    // -----------------------------------------------------------------------
    // Layer 3 — port number fallback
    // -----------------------------------------------------------------------

    fn port_fallback(&self, port: u16, detection_ms: f64) -> ServiceResult {
        let service = port_label(port).unwrap_or("unknown").to_string();
        ServiceResult {
            port,
            service,
            version: None,
            banner_raw: None,
            confidence: Confidence::PortGuess,
            detection_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Banner matching
// ---------------------------------------------------------------------------

fn match_banner(banner: &[u8], port: u16, confidence: Confidence) -> Option<ServiceResult> {
    let text = String::from_utf8_lossy(banner);
    let banner_raw = Some(sanitise_banner(banner));

    // SSH — strip protocol prefix for clean version
    if text.starts_with("SSH-") {
        let version = text.lines().next().map(|l| l.trim_end().to_string());
        return Some(ServiceResult {
            port,
            service: "ssh".into(),
            version,
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // FTP
    if text.starts_with("220") && (text.contains("FTP") || text.contains("ftp") || port == 21) {
        return Some(ServiceResult {
            port,
            service: "ftp".into(),
            version: extract_version_from_220(&text),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // SMTP
    if text.starts_with("220")
        && (text.contains("SMTP") || text.contains("smtp") || port == 25 || port == 587)
    {
        return Some(ServiceResult {
            port,
            service: "smtp".into(),
            version: extract_version_from_220(&text),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // POP3
    if text.starts_with("+OK") {
        return Some(ServiceResult {
            port,
            service: "pop3".into(),
            version: text.lines().next().map(|l| l.trim_end().to_string()),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // IMAP
    if text.starts_with("* OK") {
        return Some(ServiceResult {
            port,
            service: "imap".into(),
            version: text.lines().next().map(|l| l.trim_end().to_string()),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // Redis
    if text.starts_with("+PONG") || (text.starts_with("-ERR") && port == 6379) {
        return Some(ServiceResult {
            port,
            service: "redis".into(),
            version: None,
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // HTTP family
    if text.starts_with("HTTP/") || text.starts_with("HTTP/1") {
        // IPP / CUPS on port 631
        if port == 631 || text.contains("CUPS") || text.contains("IPP") {
            return Some(ServiceResult {
                port,
                service: "ipp".into(),
                version: extract_http_server(&text),
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Elasticsearch
        if text.contains("elasticsearch") || port == 9200 || port == 9300 {
            return Some(ServiceResult {
                port,
                service: "elasticsearch".into(),
                version: extract_http_server(&text),
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Prometheus
        if text.contains("prometheus") || port == 9090 {
            return Some(ServiceResult {
                port,
                service: "prometheus".into(),
                version: extract_http_server(&text),
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Grafana
        if port == 3000 && text.contains("Grafana") {
            return Some(ServiceResult {
                port,
                service: "grafana".into(),
                version: extract_http_server(&text),
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Kubernetes API
        if port == 6443 || (port == 8080 && text.contains("k8s")) {
            return Some(ServiceResult {
                port,
                service: "kubernetes-api".into(),
                version: None,
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Docker API
        if port == 2375 || port == 2376 {
            return Some(ServiceResult {
                port,
                service: "docker".into(),
                version: extract_json_field(&text, "Version"),
                banner_raw,
                confidence,
                detection_ms: 0.0,
            });
        }
        // Generic HTTP
        return Some(ServiceResult {
            port,
            service: "http".into(),
            version: extract_http_server(&text),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // MySQL handshake
    if banner.len() > 5 && banner[4] == 0x0a {
        return Some(ServiceResult {
            port,
            service: "mysql".into(),
            version: extract_mysql_version(banner),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // MongoDB
    if banner.len() >= 16 && port == 27017 {
        return Some(ServiceResult {
            port,
            service: "mongodb".into(),
            version: None,
            banner_raw,
            confidence: Confidence::Heuristic,
            detection_ms: 0.0,
        });
    }

    // VNC
    if text.starts_with("RFB ") {
        return Some(ServiceResult {
            port,
            service: "vnc".into(),
            version: text.lines().next().map(|l| l.trim_end().to_string()),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    // Telnet
    if banner.first() == Some(&0xFF) {
        return Some(ServiceResult {
            port,
            service: "telnet".into(),
            version: None,
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Active probe bytes — only ports we can meaningfully interpret
// ---------------------------------------------------------------------------

fn active_probe_bytes(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 8080 | 8000 | 8443 | 443 | 3000 | 4000 | 5000 | 9000 => {
            Some(b"HEAD / HTTP/1.0\r\n\r\n")
        }
        631 => Some(b"HEAD / HTTP/1.0\r\n\r\n"), // IPP/CUPS
        6379 => Some(b"PING\r\n"),               // Redis
        5432 => Some(b"\x00\x00\x00\x08\x04\xd2\x16\x2f"), // PostgreSQL
        11211 => Some(b"version\r\n"),           // Memcached
        9200 | 9300 => Some(b"GET / HTTP/1.0\r\n\r\n"), // Elasticsearch
        _ => None,                               // unknown port — skip active probe, go to fallback
    }
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

fn extract_version_from_220(text: &str) -> Option<String> {
    let line = text.lines().next()?;
    let rest = line.strip_prefix("220")?.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

fn extract_json_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let pos = text.find(&needle)?;
    let after = text[pos + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn extract_http_server(text: &str) -> Option<String> {
    for line in text.lines() {
        if line.to_lowercase().starts_with("server:") {
            return Some(line[7..].trim().to_string());
        }
    }
    None
}

fn extract_mysql_version(banner: &[u8]) -> Option<String> {
    let start = 5;
    let end = banner[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|i| start + i)?;
    String::from_utf8(banner[start..end].to_vec()).ok()
}

fn sanitise_banner(banner: &[u8]) -> String {
    banner
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Well-known port labels (Layer 3 fallback)
// ---------------------------------------------------------------------------

pub fn product_hint_from_banner(port: u16, text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    if lower.contains("ubuntu") {
        return Some(format!("{port}/tcp Ubuntu ({trimmed})"));
    }
    if lower.contains("debian") {
        return Some(format!("{port}/tcp Debian ({trimmed})"));
    }
    if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        return Some(format!("{port}/tcp Linux ({trimmed})"));
    }
    if lower.starts_with("ssh-") {
        return Some(format!("{port}/tcp {trimmed}"));
    }
    if lower.starts_with("server:") || lower.contains("apache") || lower.contains("nginx") {
        return Some(format!("{port}/tcp {trimmed}"));
    }
    None
}

pub fn service_role_label(service: &str) -> Option<&'static str> {
    match service {
        "ssh" => Some("An ssh server is running on this port"),
        "http" | "https" | "http-alt" | "https-alt" => {
            Some("A web server is running on this port")
        }
        "ftp" => Some("An ftp server is running on this port"),
        "smtp" | "smtp-submission" | "smtps" => Some("An smtp server is running on this port"),
        "pop3" | "pop3s" | "imap" | "imaps" => Some("A mail server is running on this port"),
        "mysql" | "postgresql" | "mssql" | "mongodb" | "redis" => {
            Some("A database server is running on this port")
        }
        _ => None,
    }
}

pub fn port_label(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        143 => Some("imap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        587 => Some("smtp-submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        2375 => Some("docker"),
        2376 => Some("docker-tls"),
        2379 => Some("etcd"),
        2181 => Some("zookeeper"),
        3000 => Some("http-alt"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        4369 => Some("epmd"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        6443 => Some("kubernetes-api"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        8888 => Some("http-alt"),
        9000 => Some("http-alt"),
        9090 => Some("prometheus"),
        9092 => Some("kafka"),
        9200 => Some("elasticsearch"),
        9300 => Some("elasticsearch-cluster"),
        10250 => Some("kubelet"),
        11211 => Some("memcached"),
        15672 => Some("rabbitmq-mgmt"),
        27017 => Some("mongodb"),
        50000 => Some("db2"),
        _ => None,
    }
}

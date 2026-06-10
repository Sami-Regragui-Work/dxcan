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
use std::time::Duration;
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
            Confidence::Confirmed  => write!(f, "confirmed"),
            Confidence::Heuristic  => write!(f, "heuristic"),
            Confidence::PortGuess  => write!(f, "port-guess"),
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
    pub port:        u16,
    pub service:     String,
    pub version:     Option<String>,
    pub banner_raw:  Option<String>,   // UTF-8 lossy; raw bytes hex if non-printable
    pub confidence:  Confidence,
}

// ---------------------------------------------------------------------------
// Prober
// ---------------------------------------------------------------------------

pub struct ServiceProber {
    passive_timeout: Duration,
    active_timeout:  Duration,
}

impl ServiceProber {
    /// passive_ms — how long to wait for a server-first banner
    /// active_ms  — how long to wait after sending a probe
    pub fn new(passive_ms: u64, active_ms: u64) -> Self {
        Self {
            passive_timeout: Duration::from_millis(passive_ms),
            active_timeout:  Duration::from_millis(active_ms),
        }
    }

    /// Probe a single open port. Returns a ServiceResult.
    pub async fn probe(&self, ip: IpAddr, port: u16) -> ServiceResult {
        let addr = SocketAddr::new(ip, port);

        // --- connect ---
        let stream = match timeout(self.active_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s))  => s,
            Ok(Err(_)) | Err(_) => return self.port_fallback(port),
        };

        // --- layer 1: passive grab ---
        if let Some(result) = self.passive_grab(&stream, port).await {
            return result;
        }

        // --- layer 2: active probe ---
        if let Some(result) = self.active_probe(stream, port).await {
            return result;
        }

        // --- layer 3: port fallback ---
        self.port_fallback(port)
    }

    // -----------------------------------------------------------------------
    // Layer 1 — passive grab
    // -----------------------------------------------------------------------

    async fn passive_grab(&self, stream: &TcpStream, port: u16) -> Option<ServiceResult> {
        let mut buf = vec![0u8; 1024];
        let n = match timeout(self.passive_timeout, async {
            // Safe: we only read, never write — borrow as readable
            let mut readable = stream.readable();
            // Use try_read in a loop — readable() is a hint, not a guarantee
            loop {
                readable.await.ok()?;
                match stream.try_read(&mut buf) {
                    Ok(0)  => return None,   // EOF
                    Ok(n)  => return Some(n),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        readable = stream.readable();
                        continue;
                    }
                    Err(_) => return None,
                }
            }
        }).await {
            Ok(Some(n)) => n,
            _ => return None,
        };

        let banner = &buf[..n];
        match_banner(banner, port, Confidence::Confirmed)
    }

    // -----------------------------------------------------------------------
    // Layer 2 — active probe
    // -----------------------------------------------------------------------

    async fn active_probe(&self, mut stream: TcpStream, port: u16) -> Option<ServiceResult> {
        let probe = active_probe_bytes(port)?;

        // Send probe
        if timeout(self.active_timeout, stream.write_all(probe)).await.is_err() {
            return None;
        }

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = match timeout(self.active_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };

        let banner = &buf[..n];
        match_banner(banner, port, Confidence::Heuristic)
    }

    // -----------------------------------------------------------------------
    // Layer 3 — port number fallback
    // -----------------------------------------------------------------------

    fn port_fallback(&self, port: u16) -> ServiceResult {
        let service = port_label(port).unwrap_or("unknown").to_string();
        ServiceResult {
            port,
            service,
            version:    None,
            banner_raw: None,
            confidence: Confidence::PortGuess,
        }
    }
}

// ---------------------------------------------------------------------------
// Banner matching
//
// Each matcher takes raw bytes and returns Option<(service, version)>.
// Ordered: most specific first.
// ---------------------------------------------------------------------------

fn match_banner(
    banner: &[u8],
    port: u16,
    confidence: Confidence,
) -> Option<ServiceResult> {
    let text = String::from_utf8_lossy(banner);
    let banner_raw = Some(sanitise_banner(banner));

    // SSH  — "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    if text.starts_with("SSH-") {
        let version = text.lines().next().map(|l| l.trim_end().to_string());
        return Some(ServiceResult {
            port,
            service: "ssh".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // FTP  — "220 ProFTPD 1.3.6 Server"
    if text.starts_with("220") && (text.contains("FTP") || text.contains("ftp") || port == 21) {
        let version = extract_version_from_220(&text);
        return Some(ServiceResult {
            port,
            service: "ftp".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // SMTP — "220 mail.example.com ESMTP Postfix"
    if text.starts_with("220") && (text.contains("SMTP") || text.contains("smtp") || port == 25 || port == 587) {
        let version = extract_version_from_220(&text);
        return Some(ServiceResult {
            port,
            service: "smtp".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // POP3 — "+OK Dovecot ready"
    if text.starts_with("+OK") {
        let version = text.lines().next().map(|l| l.trim_end().to_string());
        return Some(ServiceResult {
            port,
            service: "pop3".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // IMAP — "* OK Dovecot ready"
    if text.starts_with("* OK") {
        let version = text.lines().next().map(|l| l.trim_end().to_string());
        return Some(ServiceResult {
            port,
            service: "imap".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // Redis — "+PONG" or "-ERR" on PING
    if text.starts_with("+PONG") || (text.starts_with("-ERR") && port == 6379) {
        return Some(ServiceResult {
            port,
            service: "redis".into(),
            version: None,
            banner_raw,
            confidence,
        });
    }

    // HTTP — response to HEAD probe
    // "HTTP/1.1 200 OK" or any HTTP response
    if text.starts_with("HTTP/") {
        let version = extract_http_server(&text);
        return Some(ServiceResult {
            port,
            service: "http".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // MySQL — starts with a specific handshake byte sequence
    // Byte 4 is the protocol version (0x0a = MySQL 10 = protocol v10)
    if banner.len() > 5 && banner[4] == 0x0a {
        let version = extract_mysql_version(banner);
        return Some(ServiceResult {
            port,
            service: "mysql".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // MongoDB — wire protocol, starts with a specific length-prefixed message
    // Heuristic: first 4 bytes are a little-endian message length that fits
    if banner.len() >= 16 && port == 27017 {
        return Some(ServiceResult {
            port,
            service: "mongodb".into(),
            version: None,
            banner_raw,
            confidence: Confidence::Heuristic,
        });
    }

    // VNC — "RFB 003.008\n"
    if text.starts_with("RFB ") {
        let version = text.lines().next().map(|l| l.trim_end().to_string());
        return Some(ServiceResult {
            port,
            service: "vnc".into(),
            version,
            banner_raw,
            confidence,
        });
    }

    // Telnet — IAC byte (0xFF) in first bytes
    if banner.first() == Some(&0xFF) {
        return Some(ServiceResult {
            port,
            service: "telnet".into(),
            version: None,
            banner_raw,
            confidence,
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Active probe bytes per port / protocol
// ---------------------------------------------------------------------------

fn active_probe_bytes(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 8080 | 8000 | 8443 | 443 | 3000 | 4000 | 5000 | 9000 =>
            Some(b"HEAD / HTTP/1.0\r\n\r\n"),
        6379 =>
            Some(b"PING\r\n"),
        5432 =>
            // PostgreSQL startup message (simplified — triggers error banner)
            Some(b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        11211 =>
            Some(b"version\r\n"),     // Memcached
        9200 | 9300 =>
            Some(b"GET / HTTP/1.0\r\n\r\n"),  // Elasticsearch
        _ =>
            // Generic: HTTP probe — catches misconfigured services on odd ports
            Some(b"HEAD / HTTP/1.0\r\n\r\n"),
    }
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

/// Pull service/version from a 220 greeting line.
/// "220 ProFTPD 1.3.6 Server (Debian)" → "ProFTPD 1.3.6"
fn extract_version_from_220(text: &str) -> Option<String> {
    let line = text.lines().next()?;
    let rest = line.strip_prefix("220")?.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// Pull Server header from HTTP response.
/// "Server: nginx/1.24.0" → "nginx/1.24.0"
fn extract_http_server(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            return Some(line[7..].trim().to_string());
        }
    }
    None
}

/// MySQL handshake: version string starts at byte 5, null-terminated.
fn extract_mysql_version(banner: &[u8]) -> Option<String> {
    let start = 5;
    let end = banner[start..].iter().position(|&b| b == 0).map(|i| start + i)?;
    String::from_utf8(banner[start..end].to_vec()).ok()
}

/// Sanitise raw banner bytes for output.
/// Printable ASCII kept as-is; non-printable bytes shown as \xNN.
fn sanitise_banner(banner: &[u8]) -> String {
    banner.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' {
            (b as char).to_string()
        } else {
            format!("\\x{b:02x}")
        }
    }).collect()
}

// ---------------------------------------------------------------------------
// Well-known port labels (Layer 3 fallback)
// ---------------------------------------------------------------------------

fn port_label(port: u16) -> Option<&'static str> {
    match port {
        21    => Some("ftp"),
        22    => Some("ssh"),
        23    => Some("telnet"),
        25    => Some("smtp"),
        53    => Some("dns"),
        80    => Some("http"),
        110   => Some("pop3"),
        111   => Some("rpcbind"),
        143   => Some("imap"),
        389   => Some("ldap"),
        443   => Some("https"),
        445   => Some("smb"),
        465   => Some("smtps"),
        587   => Some("smtp-submission"),
        636   => Some("ldaps"),
        993   => Some("imaps"),
        995   => Some("pop3s"),
        1433  => Some("mssql"),
        1521  => Some("oracle"),
        2375  => Some("docker"),
        2376  => Some("docker-tls"),
        2379  => Some("etcd"),
        2181  => Some("zookeeper"),
        3000  => Some("http-alt"),
        3306  => Some("mysql"),
        3389  => Some("rdp"),
        4369  => Some("epmd"),      // Erlang port mapper — RabbitMQ
        5432  => Some("postgresql"),
        5672  => Some("amqp"),      // RabbitMQ
        5900  => Some("vnc"),
        6379  => Some("redis"),
        6443  => Some("kubernetes-api"),
        8080  => Some("http-alt"),
        8443  => Some("https-alt"),
        8888  => Some("http-alt"),
        9000  => Some("http-alt"),
        9092  => Some("kafka"),
        9200  => Some("elasticsearch"),
        9300  => Some("elasticsearch-cluster"),
        10250 => Some("kubelet"),
        11211 => Some("memcached"),
        15672 => Some("rabbitmq-mgmt"),
        27017 => Some("mongodb"),
        50000 => Some("db2"),
        _     => None,
    }
}
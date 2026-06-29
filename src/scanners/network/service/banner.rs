use super::types::{Confidence, ServiceResult};

pub fn active_probe_bytes(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 8080 | 8000 | 8443 | 443 | 3000 | 4000 | 5000 | 9000 => {
            Some(b"HEAD / HTTP/1.0\r\n\r\n")
        }
        631 => Some(b"HEAD / HTTP/1.0\r\n\r\n"),
        6379 => Some(b"PING\r\n"),
        5432 => Some(b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        11211 => Some(b"version\r\n"),
        9200 | 9300 => Some(b"GET / HTTP/1.0\r\n\r\n"),
        _ => None,
    }
}

pub fn match_banner(banner: &[u8], port: u16, confidence: Confidence) -> Option<ServiceResult> {
    let text = String::from_utf8_lossy(banner);
    let banner_raw = Some(sanitise_banner(banner));

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

    if text.starts_with("HTTP/") || text.starts_with("HTTP/1") {
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
        return Some(ServiceResult {
            port,
            service: "http".into(),
            version: extract_http_server(&text),
            banner_raw,
            confidence,
            detection_ms: 0.0,
        });
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::network::service::types::Confidence;

    #[test]
    fn ssh_banner_confirmed() {
        let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n";
        let r = match_banner(banner, 22, Confidence::Confirmed).unwrap();
        assert_eq!(r.service, "ssh");
        assert_eq!(r.confidence, Confidence::Confirmed);
        assert!(r.version.unwrap().starts_with("SSH-2.0"));
        assert!(r.banner_raw.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn http_head_response_heuristic() {
        let banner = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
        let r = match_banner(banner, 80, Confidence::Heuristic).unwrap();
        assert_eq!(r.service, "http");
        assert_eq!(r.version.as_deref(), Some("nginx/1.18.0"));
    }
}

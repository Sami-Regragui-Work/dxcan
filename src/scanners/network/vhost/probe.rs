use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body_len: usize,
    pub body_hash: u64,
    pub location: Option<String>,
    pub latency_ms: f64,
}

pub async fn probe_host(
    ip: IpAddr,
    port: u16,
    host_header: &str,
    path: &str,
    use_tls: bool,
    request_timeout: Duration,
) -> Result<HttpResponse, String> {
    let mut last_err = String::from("probe failed");
    for _ in 0..2 {
        match probe_host_once(ip, port, host_header, path, use_tls, request_timeout).await {
            Ok(resp) if response_usable(&resp) => return Ok(resp),
            Ok(resp) => last_err = format!("incomplete HTTP body (status {})", resp.status),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn response_usable(resp: &HttpResponse) -> bool {
    resp.status > 0 && (resp.body_len > 0 || resp.status >= 300)
}

async fn probe_host_once(
    ip: IpAddr,
    port: u16,
    host_header: &str,
    path: &str,
    use_tls: bool,
    request_timeout: Duration,
) -> Result<HttpResponse, String> {
    let start = Instant::now();
    let addr = SocketAddr::new(ip, port);
    let request = build_request(host_header, path);

    let mut buf = vec![0u8; 65536];
    let n = if use_tls {
        read_tls(addr, host_header, &request, request_timeout, &mut buf).await?
    } else {
        read_plain(addr, &request, request_timeout, &mut buf).await?
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    parse_http_response(&buf[..n], latency_ms, true)
}

fn build_request(host_header: &str, path: &str) -> Vec<u8> {
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: dxcan-vhost\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes()
}

async fn read_plain(
    addr: SocketAddr,
    request: &[u8],
    request_timeout: Duration,
    buf: &mut [u8],
) -> Result<usize, String> {
    let mut stream = timeout(request_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout to {addr}"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;

    timeout(request_timeout, read_response(&mut stream, request, buf))
        .await
        .map_err(|_| format!("read timeout from {addr}"))?
}

async fn read_tls(
    addr: SocketAddr,
    sni_host: &str,
    request: &[u8],
    request_timeout: Duration,
    buf: &mut [u8],
) -> Result<usize, String> {
    let connector = tls_connector()?;
    let stream = timeout(request_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout to {addr}"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;

    let sni = ServerName::try_from(sni_host.to_string())
        .map_err(|_| format!("invalid SNI host: {sni_host}"))?;
    let mut tls = timeout(request_timeout, connector.connect(sni, stream))
        .await
        .map_err(|_| format!("TLS handshake timeout to {addr}"))?
        .map_err(|e| format!("TLS {addr}: {e}"))?;

    timeout(request_timeout, read_response(&mut tls, request, buf))
        .await
        .map_err(|_| format!("read timeout from {addr}"))?
}

async fn read_response(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    request: &[u8],
    buf: &mut [u8],
) -> Result<usize, String> {
    stream
        .write_all(request)
        .await
        .map_err(|e| format!("write: {e}"))?;
    let idle = Duration::from_millis(1500);
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            break;
        }
        if total > 0 && http_message_complete(&buf[..total]) {
            break;
        }
        let n = match timeout(idle, stream.read(&mut buf[total..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("read: {e}")),
            Err(_) if total == 0 => return Err("read idle timeout".into()),
            Err(_) => break,
        };
        total += n;
        if http_message_complete(&buf[..total]) {
            break;
        }
    }
    Ok(total)
}

fn tls_connector() -> Result<TlsConnector, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn parse_http_response(raw: &[u8], latency_ms: f64, require_complete: bool) -> Result<HttpResponse, String> {
    if require_complete && !raw.is_empty() && !http_message_complete(raw) {
        return Err("incomplete HTTP message".into());
    }
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or("empty HTTP response")?;
    let status = parse_status_code(status_line)?;

    let mut location = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("location:") {
            location = Some(line[9..].trim().to_string());
        }
    }

    let body = extract_body(raw)?;
    let body_len = body.len();
    let body_hash = hash_bytes(&body);

    Ok(HttpResponse {
        status,
        body_len,
        body_hash,
        location,
        latency_ms,
    })
}

fn extract_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = find_body_start(raw);
    if header_end >= raw.len() {
        return Ok(Vec::new());
    }
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let wire = &raw[header_end..];
    if header_is_chunked(&headers) {
        return decode_chunked(wire).ok_or_else(|| "incomplete chunked body".into());
    }
    if let Some(cl) = header_content_length(&headers) {
        let end = wire.len().min(cl);
        return Ok(wire[..end].to_vec());
    }
    Ok(wire.to_vec())
}

fn header_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            return line.split(':').nth(1)?.trim().parse().ok();
        }
    }
    None
}

fn header_is_chunked(headers: &str) -> bool {
    headers
        .lines()
        .any(|line| line.to_ascii_lowercase().contains("transfer-encoding:") && line.to_ascii_lowercase().contains("chunked"))
}

fn decode_chunked(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let rel = data[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line_end = pos + rel;
        let size_hex = std::str::from_utf8(&data[pos..line_end])
            .ok()?
            .trim()
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if pos + size > data.len() {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        if pos + 2 > data.len() {
            return None;
        }
        pos += 2;
    }
}

fn http_message_complete(raw: &[u8]) -> bool {
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let header_end = header_end + 4;
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let body = &raw[header_end..];
    if header_is_chunked(&headers) {
        return chunked_message_complete(body);
    }
    if let Some(cl) = header_content_length(&headers) {
        return body.len() >= cl;
    }
    false
}

fn chunked_message_complete(data: &[u8]) -> bool {
    decode_chunked(data).is_some()
}

fn parse_status_code(status_line: &str) -> Result<u16, String> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line: {status_line}"))
}

fn find_body_start(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len())
}

fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

pub fn port_uses_tls(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443)
}

pub fn is_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443 | 8000 | 8080 | 8443 | 8888 | 9000 | 9443 | 3000 | 5000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_http_response(raw, 1.0, false).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body_len, 5);
    }

    #[test]
    fn parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_http_response(raw, 1.0, false).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body_len, 11);
    }

    #[test]
    fn chunked_message_done() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        assert!(chunked_message_complete(body));
    }
}

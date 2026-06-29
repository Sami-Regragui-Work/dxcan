use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::banner::{active_probe_bytes, match_banner};
use super::labels::port_label;
use super::types::{Confidence, ServiceResult};

pub struct ServiceProber {
    passive_timeout: Duration,
    active_timeout: Duration,
}

impl ServiceProber {
    pub fn new(passive_ms: u64, active_ms: u64) -> Self {
        Self {
            passive_timeout: Duration::from_millis(passive_ms),
            active_timeout: Duration::from_millis(active_ms),
        }
    }

    pub async fn probe(&self, ip: IpAddr, port: u16) -> ServiceResult {
        let start = Instant::now();
        let addr = SocketAddr::new(ip, port);

        let stream = match timeout(self.active_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                return self.port_fallback(port, start.elapsed().as_secs_f64() * 1000.0);
            }
        };

        if let Some(mut result) = self.passive_grab(&stream, port).await {
            result.detection_ms = start.elapsed().as_secs_f64() * 1000.0;
            return result;
        }

        if let Some(mut result) = self.active_probe(stream, port).await {
            result.detection_ms = start.elapsed().as_secs_f64() * 1000.0;
            return result;
        }

        self.port_fallback(port, start.elapsed().as_secs_f64() * 1000.0)
    }

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

        match_banner(&buf[..n], port, Confidence::Confirmed)
    }

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

        match_banner(&buf[..n], port, Confidence::Heuristic)
    }

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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::scanners::network::service::types::Confidence;

    #[tokio::test]
    async fn scanme_ssh_sv_timing() {
        let ip: std::net::IpAddr = "45.33.32.156".parse().expect("scanme ipv4");

        let prober = ServiceProber::new(500, 5000);
        let wall_start = Instant::now();
        let r = prober.probe(ip, 22).await;
        let wall_ms = wall_start.elapsed().as_secs_f64() * 1000.0;

        assert_eq!(r.port, 22);
        assert_eq!(r.service, "ssh");
        assert_eq!(r.confidence, Confidence::Confirmed);
        assert!(r.version.is_some(), "expected SSH version banner");
        assert!(r.banner_raw.is_some(), "expected raw banner");
        assert!(r.detection_ms > 0.0, "detection_ms should be recorded");
        assert!(
            r.detection_ms <= wall_ms + 100.0,
            "detection_ms {} should not exceed wall {} by much",
            r.detection_ms,
            wall_ms
        );
        assert!(
            r.detection_ms < 10_000.0,
            "detection_ms {} looks stuck or timed out wrong",
            r.detection_ms
        );
        assert!(
            wall_ms < 12_000.0,
            "wall probe took {}ms — service path too slow",
            wall_ms
        );
    }
}

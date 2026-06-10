use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::output::PortResult;
use crate::scanner::rtt::RttTracker;

pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.parse::<u32>(), b.parse::<u32>()) {
                for p in lo..=hi {
                    if (1..=65535).contains(&p) {
                        ports.insert(p as u16);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u32>() {
            if (1..=65535).contains(&p) {
                ports.insert(p as u16);
            }
        }
    }
    ports.into_iter().collect()
}

pub async fn scan_port(
    ip: IpAddr,
    port: u16,
    base_dur: Duration,
    sem: Arc<Semaphore>,
    rtt: Arc<Mutex<RttTracker>>,
) -> PortResult {
    let _permit = sem.acquire().await.unwrap();

    let dur = {
        let tracker = rtt.lock().unwrap();
        tracker
            .timeout_ms()
            .map(|ms| Duration::from_secs_f64(ms / 1000.0))
            .unwrap_or(base_dur)
            .min(base_dur)
    };

    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();

    let connect_result = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    match connect_result {
        Ok(_) => {
            rtt.lock().unwrap().update(latency_ms);
            PortResult { port, state: "open".into(), latency_ms, error: None }
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            rtt.lock().unwrap().update(latency_ms);
            PortResult { port, state: "closed".into(), latency_ms, error: None }
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            PortResult { port, state: "filtered".into(), latency_ms, error: None }
        }
        Err(e) => {
            PortResult { port, state: "error".into(), latency_ms, error: Some(e.to_string()) }
        }
    }
}
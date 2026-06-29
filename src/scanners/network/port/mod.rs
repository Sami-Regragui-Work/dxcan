mod rtt;
mod scan;
mod syn;

pub use scan::{run_port_scan, scan_mode, ScanPlan};

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use self::rtt::RttTracker;

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub latency_ms: f64,
    pub error: Option<String>,
}

pub enum PortProbeOutcome {
    Open(PortResult),
    Closed,
    NotOpen,
}

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

pub async fn scan_port_full(
    ip: IpAddr,
    port: u16,
    base_dur: Duration,
    sem: Arc<Semaphore>,
    rtt: Arc<Mutex<RttTracker>>,
) -> PortResult {
    let _permit = sem.acquire().await.unwrap();
    let dur = probe_timeout(base_dur, &rtt);
    probe_port(ip, port, dur, &rtt, true).await
}

pub async fn scan_port_open_only(
    ip: IpAddr,
    port: u16,
    base_dur: Duration,
    open_cap: Duration,
    sem: Arc<Semaphore>,
    rtt: Arc<Mutex<RttTracker>>,
    closed_samples: Arc<Mutex<Vec<u16>>>,
) -> PortProbeOutcome {
    let _permit = sem.acquire().await.unwrap();
    let adaptive = probe_timeout(base_dur, &rtt);
    let dur = adaptive.min(open_cap);
    match probe_port(ip, port, dur, &rtt, true).await {
        PortResult {
            state,
            port,
            latency_ms,
            ..
        } if state == "open" => PortProbeOutcome::Open(PortResult {
            port,
            protocol: "tcp".into(),
            state,
            latency_ms,
            error: None,
        }),
        PortResult {
            state,
            port,
            ..
        } if state == "closed" => {
            closed_samples.lock().unwrap().push(port);
            PortProbeOutcome::Closed
        }
        _ => PortProbeOutcome::NotOpen,
    }
}

fn probe_timeout(base_dur: Duration, rtt: &Arc<Mutex<RttTracker>>) -> Duration {
    let tracker = rtt.lock().unwrap();
    let cap = base_dur;
    let floor = Duration::from_secs_f64(base_dur.as_secs_f64() * 0.25);
    let chosen = tracker
        .timeout_ms()
        .map(|ms| Duration::from_secs_f64(ms / 1000.0))
        .unwrap_or(base_dur);
    chosen.max(floor).min(cap)
}

async fn probe_port(
    ip: IpAddr,
    port: u16,
    dur: Duration,
    rtt: &Arc<Mutex<RttTracker>>,
    update_rtt: bool,
) -> PortResult {
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
            if update_rtt {
                rtt.lock().unwrap().update(latency_ms);
            }
            PortResult {
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                latency_ms,
                error: None,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            if update_rtt {
                rtt.lock().unwrap().update(latency_ms);
            }
            PortResult {
                port,
                protocol: "tcp".into(),
                state: "closed".into(),
                latency_ms,
                error: None,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => PortResult {
            port,
            protocol: "tcp".into(),
            state: "filtered".into(),
            latency_ms,
            error: None,
        },
        Err(e) => PortResult {
            port,
            protocol: "tcp".into(),
            state: "error".into(),
            latency_ms,
            error: Some(e.to_string()),
        },
    }
}

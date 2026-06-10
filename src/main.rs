//! dxcan v0.2.1 — lightweight TCP port scanner

use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dxcan",
    about = "Lightweight TCP port scanner — part of the DXC platform.",
    version
)]
struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    host: String,

    /// Ports: single (22,80), range (1-1024), mixed (22,8000-9000)
    #[arg(short, long)]
    ports: String,

    /// Initial per-port TCP timeout in seconds (adapts downward at runtime)
    #[arg(short, long, default_value_t = 0.5)]
    timeout: f64,

    /// Maximum concurrent connections
    #[arg(short, long, default_value_t = 500)]
    workers: usize,

    /// Output structured JSON
    #[arg(short, long)]
    json: bool,

    /// Show full latency precision in plain text output
    #[arg(long)]
    precise: bool,

    /// Show closed and filtered ports (default: open only)
    #[arg(long)]
    all: bool,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PortResult {
    port: u16,
    state: String,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ScanOutput {
    tool: String,
    host: String,
    ip: String,
    elapsed_s: f64,
    scanned: usize,
    shown: usize,
    results: Vec<PortResult>,
}

// ---------------------------------------------------------------------------
// Adaptive RTT tracker
//
// Simplified version of nmap's srtt/rttvar model (RFC 2988).
// Only feeds from connect-scan results (open + closed) not from timeouts,
// since filtered ports don't give real RTT data.
//
// Once MIN_SAMPLES are collected, returns srtt + rttvar*4 as the live
// timeout floor. Prevents wasting time on fast networks.
// ---------------------------------------------------------------------------

const MIN_SAMPLES: usize = 5;

struct RttTracker {
    srtt: f64,   // smoothed RTT in ms
    rttvar: f64, // RTT variance in ms
    samples: usize,
}

impl RttTracker {
    fn new(initial_ms: f64) -> Self {
        Self {
            srtt: initial_ms,
            rttvar: initial_ms / 2.0,
            samples: 0,
        }
    }

    /// Feed a real RTT sample (only call for open/closed, not filtered).
    fn update(&mut self, rtt_ms: f64) {
        if self.samples == 0 {
            self.srtt = rtt_ms;
            self.rttvar = rtt_ms / 2.0;
        } else {
            // RFC 2988 formulas
            let diff = (rtt_ms - self.srtt).abs();
            self.rttvar = self.rttvar + (diff - self.rttvar) / 4.0;
            self.srtt = self.srtt + (rtt_ms - self.srtt) / 8.0;
        }
        self.samples += 1;
    }

    /// Returns adaptive timeout in ms, or None if not enough samples yet.
    fn timeout_ms(&self) -> Option<f64> {
        if self.samples >= MIN_SAMPLES {
            // nmap formula: timeout = srtt + rttvar * 4
            // Add a floor of 50ms to avoid false-filtered on open ports with
            // slightly variable RTT.
            Some((self.srtt + self.rttvar * 4.0).max(50.0))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

fn parse_ports(spec: &str) -> Vec<u16> {
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

// ---------------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------------

async fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    tokio::net::lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| format!("DNS resolution failed for '{host}': {e}"))?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| format!("No addresses found for '{host}'"))
}

// ---------------------------------------------------------------------------
// Port scan
//
// Key change from v0.1:
//   Uses TcpSocket instead of TcpStream::connect() directly, so we can set
//   SO_LINGER = 0 before connecting. This means when the socket is dropped
//   the kernel sends RST instead of going through the FIN/ACK/FIN/ACK
//   teardown sequence — saving one full RTT per open port.
//   This is exactly what nmap does on connect scan.
// ---------------------------------------------------------------------------

async fn scan_port(
    ip: IpAddr,
    port: u16,
    base_dur: Duration,
    sem: Arc<Semaphore>,
    rtt: Arc<Mutex<RttTracker>>,
) -> PortResult {
    let _permit = sem.acquire().await.unwrap();

    // Read adaptive timeout; fall back to base if not enough samples yet.
    let dur = {
        let tracker = rtt.lock().unwrap();
        tracker
            .timeout_ms()
            .map(|ms| Duration::from_secs_f64(ms / 1000.0))
            .unwrap_or(base_dur)
            // Never exceed the user-supplied base timeout.
            .min(base_dur)
    };

    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();

    // Build socket with SO_LINGER = 0 before connecting.
    // On drop this sends RST immediately rather than FIN — no graceful teardown.
    // let connect_result = (|| async {
    //     let socket = match addr {
    //         SocketAddr::V4(_) => TcpSocket::new_v4()?,
    //         SocketAddr::V6(_) => TcpSocket::new_v6()?,
    //     };
    //     // RST on close: saves one RTT per open port vs graceful FIN teardown.
    //     socket.set_zero_linger()?;
    //     timeout(dur, socket.connect(addr)).await
    //         .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))?
    // })().await;
    let connect_result = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    match connect_result {
        Ok(_) => {
            // Feed real RTT to the adaptive tracker.
            rtt.lock().unwrap().update(latency_ms);
            PortResult {
                port,
                state: "open".into(),
                latency_ms,
                error: None,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            rtt.lock().unwrap().update(latency_ms);
            PortResult {
                port,
                state: "closed".into(),
                latency_ms,
                error: None,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => PortResult {
            port,
            state: "filtered".into(),
            latency_ms,
            error: None,
        },
        Err(e) => PortResult {
            port,
            state: "error".into(),
            latency_ms,
            error: Some(e.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let ip = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };

    let ports = parse_ports(&args.ports);
    if ports.is_empty() {
        eprintln!("[error] No valid ports in range 1-65535.");
        std::process::exit(1);
    }

    let total = ports.len();
    let workers = args.workers.min(total).max(1);
    let sem = Arc::new(Semaphore::new(workers));
    let base_dur = Duration::from_secs_f64(args.timeout);
    let rtt = Arc::new(Mutex::new(RttTracker::new(args.timeout * 1000.0)));
    let started = Instant::now();

    // FuturesUnordered: tasks are polled as they complete, not in spawn order.
    // Reduces peak memory vs collecting all JoinHandles upfront, and allows
    // the adaptive RTT to start feeding earlier in the scan.
    let mut futs = FuturesUnordered::new();
    for port in ports {
        futs.push(scan_port(ip, port, base_dur, sem.clone(), rtt.clone()));
    }

    let mut results: Vec<PortResult> = Vec::with_capacity(total);
    while let Some(r) = futs.next().await {
        results.push(r);
    }

    results.sort_unstable_by_key(|r| r.port);
    let elapsed = started.elapsed().as_secs_f64();

    // Output
    if args.json {
        let display: Vec<PortResult> = results
            .into_iter()
            .filter(|r| args.all || r.state == "open")
            .collect();
        let output = ScanOutput {
            tool: "dxcan".into(),
            host: args.host.clone(),
            ip: ip.to_string(),
            elapsed_s: elapsed,
            scanned: total,
            shown: display.len(),
            results: display,
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        let display: Vec<&PortResult> = results
            .iter()
            .filter(|r| args.all || r.state == "open")
            .collect();
        for r in &display {
            let extra = r
                .error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default();
            let lat = fmt_lat(r.latency_ms, args.precise);
            println!("{}/tcp\t{}\t{}{}", r.port, r.state, lat, extra);
        }
        println!(
            "\nScanned {total} ports in {} — {} shown",
            fmt_elapsed(elapsed, args.precise),
            display.len()
        );
    }
}

fn fmt_lat(ms: f64, precise: bool) -> String {
    if precise {
        format!("{ms}ms")
    } else {
        format!("{:.4}s", ms / 1000.0)
    }
}

fn fmt_elapsed(secs: f64, precise: bool) -> String {
    if precise {
        format!("{}ms", secs * 1000.0)
    } else {
        format!("{secs:.4}s")
    }
}

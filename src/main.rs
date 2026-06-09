//! dxcan — lightweight TCP port scanner
//!
//! Usage:
//!   dxcan -H 127.0.0.1 -p 22,80,443
//!   dxcan -H localhost -p 1-1024 -t 0.5 -w 500
//!   dxcan -H 127.0.0.1 -p 1-65535 -w 1000 --json
//!   dxcan -H 127.0.0.1 -p 1-1024 --all
//!
//! Port formats:
//!   Single : 22,80,443
//!   Range  : 1-1024
//!   Mixed  : 22,80,443,8000-9000

use clap::Parser;
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name    = "dxcan",
    about   = "Lightweight TCP port scanner — part of the DXC platform.",
    version
)]
struct Args {
    /// Target host to scan (IP address or hostname)
    #[arg(short = 'H', long)]
    host: String,

    /// Ports: single (22,80), range (1-1024), mixed (22,8000-9000)
    #[arg(short, long)]
    ports: String,

    /// Per-port TCP timeout in seconds
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
    port:       u16,
    state:      String,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ScanOutput {
    tool:      String,
    host:      String,
    ip:        String,
    elapsed_s: f64,
    scanned:   usize,
    shown:     usize,
    results:   Vec<PortResult>,
}

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

/// Parse "22,80,443", "1-1024", or "22,8000-9000" into a sorted Vec<u16>.
/// Values outside 1–65535 are silently dropped.
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

/// Resolve hostname → IpAddr.
/// Tries direct parse first (IP literal), then async DNS.
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
// ---------------------------------------------------------------------------

/// Attempt a TCP connection and return its state.
///
/// States:
///   open     — connection accepted
///   closed   — connection refused (RST)
///   filtered — no response within timeout
///   error    — unexpected error (reason included)
async fn scan_port(ip: IpAddr, port: u16, dur: Duration, sem: Arc<Semaphore>) -> PortResult {
    // Acquire a concurrency slot before touching the network.
    let _permit = sem.acquire().await.unwrap();

    let addr  = SocketAddr::new(ip, port);
    let start = Instant::now();

    match timeout(dur, TcpStream::connect(addr)).await {
        // Connection accepted
        Ok(Ok(_)) => PortResult {
            port,
            state:      "open".into(),
            latency_ms: ms(start),
            error:      None,
        },

        // Connection refused — port is reachable but not listening
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortResult {
            port,
            state:      "closed".into(),
            latency_ms: ms(start),
            error:      None,
        },

        // Any other OS error
        Ok(Err(e)) => PortResult {
            port,
            state:      "error".into(),
            latency_ms: ms(start),
            error:      Some(e.to_string()),
        },

        // Timeout elapsed — likely firewalled
        Err(_) => PortResult {
            port,
            state:      "filtered".into(),
            latency_ms: ms(start),
            error:      None,
        },
    }
}

#[inline]
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Resolve host
    let ip = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };

    // Parse and validate ports
    let ports = parse_ports(&args.ports);
    if ports.is_empty() {
        eprintln!("[error] No valid ports in range 1-65535.");
        std::process::exit(1);
    }

    let total   = ports.len();
    let workers = args.workers.min(total).max(1);
    let sem     = Arc::new(Semaphore::new(workers));
    let dur     = Duration::from_secs_f64(args.timeout);
    let started = Instant::now();

    // Spawn one task per port; semaphore caps concurrency
    let mut handles = Vec::with_capacity(total);
    for port in ports {
        handles.push(tokio::spawn(scan_port(ip, port, dur, sem.clone())));
    }

    // Collect results
    let mut results: Vec<PortResult> = Vec::with_capacity(total);
    for h in handles {
        results.push(h.await.unwrap());
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
            tool:      "dxcan".into(),
            host:      args.host.clone(),
            ip:        ip.to_string(),
            elapsed_s: elapsed,
            scanned:   total,
            shown:     display.len(),
            results:   display,
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        let display: Vec<&PortResult> = results
            .iter()
            .filter(|r| args.all || r.state == "open")
            .collect();

        for r in &display {
            let extra = r.error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default();
            let lat   = fmt_lat(r.latency_ms, args.precise);
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
//! dxcan — DXC platform entry point

mod cli;
mod output;
mod resolver;
mod scanner;

use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use cli::Args;
use output::{PortResult, ScanOutput};
use resolver::resolve_host;
use scanner::port::{parse_ports, scan_port};
use scanner::rtt::RttTracker;

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
            let extra = r.error.as_deref()
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
    if precise { format!("{ms}ms") } else { format!("{:.4}s", ms / 1000.0) }
}

fn fmt_elapsed(secs: f64, precise: bool) -> String {
    if precise { format!("{}ms", secs * 1000.0) } else { format!("{secs:.4}s") }
}
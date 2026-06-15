//! dxcan — DXC platform entry point (native TCP scanner)

mod cli;
mod output;
mod resolver;
mod scanners;

use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use cli::Args;
use output::{PortEntry, ScanOutput};
use resolver::resolve_host;
use scanners::network::port::PortResult;
use scanners::network::{
    port::{parse_ports, scan_port},
    rtt::RttTracker,
    service::ServiceProber,
};

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

    let total   = ports.len();
    let workers = args.workers.min(total).max(1);
    let sem     = Arc::new(Semaphore::new(workers));
    let base_dur = Duration::from_secs_f64(args.timeout);
    let rtt     = Arc::new(Mutex::new(RttTracker::new(args.timeout * 1000.0)));
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
    let elapsed = started.elapsed().as_millis() as f64;

    // Stage 2: service detection on open ports
    let prober = ServiceProber::new(500, 1000);
    let mut service_futs = FuturesUnordered::new();
    for r in results.iter().filter(|r| r.state == "open") {
        service_futs.push(prober.probe(ip, r.port));
    }
    let mut services: HashMap<u16, scanners::network::service::ServiceResult> = HashMap::new();
    while let Some(s) = service_futs.next().await {
        services.insert(s.port, s);
    }

    // Output
    let display: Vec<PortEntry> = results
        .iter()
        .filter(|r| args.all || r.state == "open")
        .map(|r| {
            let svc = services.get(&r.port);
            PortEntry {
                port:       r.port,
                protocol:   r.protocol.clone(),
                state:      r.state.clone(),
                latency_ms: r.latency_ms,
                service:    svc.map(|s| s.service.clone()),
                version:    svc.and_then(|s| s.version.clone()),
                banner_raw: svc.and_then(|s| s.banner_raw.clone()),
                confidence: svc.map(|s| s.confidence.to_string()),
                error:      r.error.clone(),
            }
        })
        .collect();

    if args.json {
        let output = ScanOutput {
            tool:       "dxcan".into(),
            host:       args.host.clone(),
            ip:         ip.to_string(),
            elapsed_ms: elapsed,
            scanned:    total,
            shown:      display.len(),
            results:    display,
            os_guess:   None, // native scanner doesn't do OS detection
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("dxcan scan report for {} ({})", args.host, ip);
        println!("Scanned {total} ports\n");
        println!(
            "{:<10} {:<10} {:<13} {:<22} {:<28} {}",
            "PORT", "STATE", "LATENCY", "SERVICE", "VERSION", "CONFIDENCE"
        );
        println!("{}", "-".repeat(99));

        for e in &display {
            let service    = e.service.as_deref().unwrap_or("unknown");
            let version    = e.version.as_deref().unwrap_or("");
            let confidence = e.confidence.as_deref().unwrap_or("");
            let lat        = fmt_duration(e.latency_ms, args.precise);
            println!(
                "{:<10} {:<10} {:<13} {:<22} {:<28} [{}]",
                format!("{}/{}", e.port, e.protocol),
                e.state,
                lat,
                service,
                version,
                confidence
            );
        }

        println!(
            "\n{} shown — scanned in {}",
            display.len(),
            fmt_duration(elapsed, args.precise)
        );
    }
}

fn fmt_duration(ms: f64, precise: bool) -> String {
    if precise {
        format!("{:.6}ms", ms)
    } else {
        format!("{:.4}s", ms / 1000.0)
    }
}
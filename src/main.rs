//! dxcan 0.4.0 — DXC platform entry point (native TCP scanner)

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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let t0 = Instant::now();

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

    // ── Phase 1: port scan ────────────────────────────────────────────────
    let scan_start = Instant::now();

    let mut futs = FuturesUnordered::new();
    for port in ports {
        futs.push(scan_port(ip, port, base_dur, sem.clone(), rtt.clone()));
    }

    let mut results: Vec<PortResult> = Vec::with_capacity(total);
    while let Some(r) = futs.next().await {
        results.push(r);
    }
    results.sort_unstable_by_key(|r| r.port);

    let scan_ms = scan_start.elapsed().as_secs_f64() * 1000.0;

    // ── Phase 2: service detection ────────────────────────────────────────
    // Derive timeout from observed RTT: max(rtt * 10, 20ms), cap at 500ms
    let max_rtt_ms = results
        .iter()
        .filter(|r| r.state == "open")
        .map(|r| r.latency_ms)
        .fold(0.0_f64, f64::max);

    let service_passive_ms = ((max_rtt_ms * 10.0).max(20.0).min(500.0)) as u64;
    let service_active_ms = ((max_rtt_ms * 10.0).max(20.0).min(500.0)) as u64;

    let service_start = Instant::now();
    let prober = ServiceProber::new(service_passive_ms, service_active_ms);

    let mut service_futs = FuturesUnordered::new();
    for r in results.iter().filter(|r| r.state == "open") {
        service_futs.push(prober.probe(ip, r.port));
    }

    let mut services: HashMap<u16, scanners::network::service::ServiceResult> = HashMap::new();
    while let Some(s) = service_futs.next().await {
        services.insert(s.port, s);
    }

    let service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // ── Build display entries ─────────────────────────────────────────────
    let display: Vec<PortEntry> = results
        .iter()
        .filter(|r| args.all || r.state == "open")
        .map(|r| {
            let svc = services.get(&r.port);
            // Combined latency: connect + service detection for this port
            let total_latency = r.latency_ms + svc.map(|s| s.detection_ms).unwrap_or(0.0);
            PortEntry {
                port: r.port,
                protocol: r.protocol.clone(),
                state: r.state.clone(),
                latency_ms: total_latency,
                service: svc.map(|s| s.service.clone()),
                version: svc.and_then(|s| s.version.clone()),
                banner_raw: svc.and_then(|s| s.banner_raw.clone()),
                confidence: svc.map(|s| s.confidence.to_string()),
                error: r.error.clone(),
            }
        })
        .collect();

    // ── Output ────────────────────────────────────────────────────────────
    if args.json {
        let output = ScanOutput {
            tool: "dxcan".into(),
            host: args.host.clone(),
            ip: ip.to_string(),
            elapsed_ms: wall_ms,
            scanned: total,
            shown: display.len(),
            results: display,
            os_guess: None,
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        if args.host != ip.to_string() {
            println!("dxcan scan report for {} ({})", args.host, ip);
        } else {
            println!("dxcan scan report for {}", args.host);
        }
        println!("Scanned {total} ports\n");

        println!(
            "{:<10} {:<10} {:<13} {:<22} {:<42} {}",
            "PORT", "STATE", "LATENCY", "SERVICE", "VERSION", "CONFIDENCE"
        );
        println!("{}", "-".repeat(113));

        for e in &display {
            let service = e.service.as_deref().unwrap_or("unknown");
            let version = e.version.as_deref().unwrap_or("");
            let confidence = e.confidence.as_deref().unwrap_or("");
            let lat = fmt_duration(e.latency_ms, args.precise);
            println!(
                "{:<10} {:<10} {:<13} {:<22} {:<42} [{}]",
                format!("{}/{}", e.port, e.protocol),
                e.state,
                lat,
                service,
                version,
                confidence,
            );
        }

        println!(
            "\n{} shown — scanned in {}. Per port latencies are happening concurrently",
            display.len(),
            fmt_duration(wall_ms, args.precise)
        );

        // ── Debug block ───────────────────────────────────────────────────
        if args.debug {
            println!("\n--- debug ---");
            println!("connect total:   {}", fmt_duration(scan_ms, true));
            println!("service total:   {}", fmt_duration(service_ms, true));
            println!(
                "sum total:       {}",
                fmt_duration(scan_ms + service_ms, true)
            );
            println!("wall total:      {}", fmt_duration(wall_ms, true));
            println!(
                "service timeout: passive={}ms  active={}ms  (derived from max RTT {:.2}ms)",
                service_passive_ms, service_active_ms, max_rtt_ms
            );
        }
    }
}

fn fmt_duration(ms: f64, precise: bool) -> String {
    if precise {
        format!("{ms:.3}ms")
    } else if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else {
        format!("{ms:.1}ms")
    }
}

//! dxcan 0.5.0 — DXC platform entry point (native TCP scanner)

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
    service::{port_label, ServiceProber},
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

    let open_ports: Vec<&PortResult> = results.iter().filter(|r| r.state == "open").collect();

    // ── Phase 2: service detection (optional) ─────────────────────────────
    // Default: pure port-number → service name lookup (zero extra connections)
    // --service-version: full 3-layer banner probe (produces version + confidence)

    let max_rtt_ms = open_ports
        .iter()
        .map(|r| r.latency_ms)
        .fold(0.0_f64, f64::max);

    let service_ms;
    let service_passive_ms = ((max_rtt_ms * 10.0).max(20.0).min(500.0)) as u64;
    let service_active_ms = service_passive_ms;

    // service map: port → (service_name, version, banner_raw, confidence, detection_ms)
    struct ServiceInfo {
        service: String,
        version: Option<String>,
        banner_raw: Option<String>,
        confidence: Option<String>,
        detection_ms: f64,
    }

    let services: HashMap<u16, ServiceInfo> = if args.service_version {
        let service_start = Instant::now();
        let prober = ServiceProber::new(service_passive_ms, service_active_ms);

        let mut sfuts = FuturesUnordered::new();
        for r in &open_ports {
            sfuts.push(prober.probe(ip, r.port));
        }

        let mut map = HashMap::new();
        while let Some(s) = sfuts.next().await {
            map.insert(
                s.port,
                ServiceInfo {
                    service: s.service,
                    version: s.version,
                    banner_raw: s.banner_raw,
                    confidence: Some(s.confidence.to_string()),
                    detection_ms: s.detection_ms,
                },
            );
        }
        service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
        map
    } else {
        // Fast path: table lookup only, no connections
        service_ms = 0.0;
        open_ports
            .iter()
            .map(|r| {
                let name = port_label(r.port).unwrap_or("unknown").to_string();
                (
                    r.port,
                    ServiceInfo {
                        service: name,
                        version: None,
                        banner_raw: None,
                        confidence: None,
                        detection_ms: 0.0,
                    },
                )
            })
            .collect()
    };

    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // ── Build display entries ─────────────────────────────────────────────
    let display: Vec<PortEntry> = results
        .iter()
        .filter(|r| args.all || r.state == "open")
        .map(|r| {
            let svc = services.get(&r.port);
            let total_latency = r.latency_ms + svc.map(|s| s.detection_ms).unwrap_or(0.0);
            PortEntry {
                port: r.port,
                protocol: r.protocol.clone(),
                state: r.state.clone(),
                latency_ms: total_latency,
                service: svc.map(|s| s.service.clone()),
                version: if args.service_version {
                    svc.and_then(|s| s.version.clone())
                } else {
                    None
                },
                banner_raw: if args.service_version {
                    svc.and_then(|s| s.banner_raw.clone())
                } else {
                    None
                },
                confidence: if args.service_version {
                    svc.and_then(|s| s.confidence.clone())
                } else {
                    None
                },
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

        if args.service_version {
            // Wide table: PORT STATE LATENCY SERVICE VERSION CONFIDENCE
            println!(
                "{:<10} {:<10} {:<13} {:<22} {:<42} {}",
                "PORT", "STATE", "LATENCY", "SERVICE", "VERSION", "CONFIDENCE"
            );
            println!("{}", "-".repeat(113));
            for e in &display {
                println!(
                    "{:<10} {:<10} {:<13} {:<22} {:<42} [{}]",
                    format!("{}/{}", e.port, e.protocol),
                    e.state,
                    fmt_duration(e.latency_ms, args.precise),
                    e.service.as_deref().unwrap_or("unknown"),
                    e.version.as_deref().unwrap_or(""),
                    e.confidence.as_deref().unwrap_or(""),
                );
            }
        } else {
            // Default table: PORT STATE LATENCY SERVICE
            println!(
                "{:<10} {:<10} {:<13} {}",
                "PORT", "STATE", "LATENCY", "SERVICE"
            );
            println!("{}", "-".repeat(50));
            for e in &display {
                println!(
                    "{:<10} {:<10} {:<13} {}",
                    format!("{}/{}", e.port, e.protocol),
                    e.state,
                    fmt_duration(e.latency_ms, args.precise),
                    e.service.as_deref().unwrap_or("unknown"),
                );
            }
        }

        println!(
            "\n{} shown — scanned in {}",
            display.len(),
            fmt_duration(wall_ms, args.precise)
        );

        // ── Debug block ───────────────────────────────────────────────────
        if args.debug {
            println!("\n--- debug ---");
            println!("connect total:   {}", fmt_duration(scan_ms, true));
            if args.service_version {
                println!("service total:   {}", fmt_duration(service_ms, true));
                println!(
                    "service timeout: passive={}ms  active={}ms  (derived from max RTT {:.2}ms)",
                    service_passive_ms, service_active_ms, max_rtt_ms
                );
            }
            println!("wall total:      {}", fmt_duration(wall_ms, true));
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

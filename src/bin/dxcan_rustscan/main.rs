//! dxcan-rustscan — RustScan-backed scanner.
//!
//! Two-phase pipeline:
//!   1. RustScan — fast port discovery
//!   2. Nmap     — service/version/OS detection on discovered ports only

mod cli;
mod nmap_runner;
mod nmap_xml;
mod output;
mod rustscan_runner;

use clap::Parser;
use cli::Args;
use output::{PortEntry, ScanOutput};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // --- dry-run ---
    if args.dry_run {
        let rs_cfg = build_rs_config(&args);
        let rs_args = rustscan_runner::build_args(&rs_cfg);
        println!("rustscan {}", rs_args.join(" "));
        println!("# (then nmap is called with discovered ports)");
        return;
    }

    // --- check tools are available ---
    match rustscan_runner::check_rustscan().await {
        Ok(v) => eprintln!("[dxcan-rustscan] using {v}"),
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    }
    match nmap_runner::check_nmap().await {
        Ok(v) => eprintln!("[dxcan-rustscan] using {v}"),
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    }

    let wall_start = Instant::now();

    if !args.json {
        eprintln!(
            "[dxcan-rustscan] phase 1 — port discovery on {} ...",
            args.host
        );
    }

    // -----------------------------------------------------------------------
    // Phase 1: RustScan — port discovery
    // -----------------------------------------------------------------------
    let rs_cfg = build_rs_config(&args);
    let scan_timeout = std::time::Duration::from_secs(args.scan_timeout);

    let open_ports = match rustscan_runner::run(&rs_cfg, scan_timeout).await {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("[error] RustScan failed: {e}");
            std::process::exit(1);
        }
    };

    let phase1_ms = wall_start.elapsed().as_millis() as f64;

    if open_ports.is_empty() {
        if !args.json {
            eprintln!("[dxcan-rustscan] no open ports found");
        }
        let out = ScanOutput {
            tool: "dxcan-rustscan".into(),
            host: args.host.clone(),
            ip: args.host.clone(),
            elapsed_ms: phase1_ms,
            scanned: 0,
            shown: 0,
            results: vec![],
            os_guess: None,
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            println!("dxcan-rustscan: no open ports on {}", args.host);
            if args.debug {
                println!("\n--- debug ---");
                println!("phase 1 (rustscan): {:.3}ms", phase1_ms);
                println!("wall total:         {:.3}ms", phase1_ms);
            }
        }
        return;
    }

    if !args.json {
        eprintln!(
            "[dxcan-rustscan] phase 1 done in {}ms — {} open port(s): {}",
            phase1_ms as u64,
            open_ports.len(),
            open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        eprintln!("[dxcan-rustscan] phase 2 — service detection via Nmap ...");
    }

    // -----------------------------------------------------------------------
    // Phase 2: Nmap — on open ports only
    // -----------------------------------------------------------------------
    let port_spec = open_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let nmap_cfg = nmap_runner::NmapConfig {
        host: args.host.clone(),
        ports: port_spec,
        service_detection: args.service_version,
        os_detection: args.os,
        version_intensity: args.intensity,
        scan_timeout,
        timing: args.timing,
        extra_args: args.extra.clone(),
    };

    let raw = match nmap_runner::run(&nmap_cfg).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] Nmap failed: {e}");
            std::process::exit(1);
        }
    };

    let wall_ms = wall_start.elapsed().as_millis() as f64;
    let phase2_ms = wall_ms - phase1_ms;

    if !raw.stderr.is_empty() {
        for line in raw.stderr.lines() {
            if line.starts_with("Starting Nmap")
                || line.starts_with("Nmap scan report")
                || line.starts_with("Note:")
            {
                continue;
            }
            eprintln!("[nmap] {line}");
        }
    }

    if raw.xml.is_empty() {
        eprintln!(
            "[error] Nmap produced no XML output (exit code {})",
            raw.exit_code
        );
        if raw.exit_code == 1 {
            eprintln!("[hint] OS detection (--os) requires root or CAP_NET_RAW.");
        }
        std::process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Parse and emit
    // -----------------------------------------------------------------------
    let parsed = match nmap_xml::parse(&raw.xml) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] XML parse failed: {e}");
            std::process::exit(1);
        }
    };

    let host = match parsed.hosts.into_iter().next() {
        Some(h) => h,
        None => {
            eprintln!("[error] No host results in Nmap output.");
            std::process::exit(1);
        }
    };

    let nmap_elapsed_ms = parsed.elapsed_secs.map(|s| s * 1000.0).unwrap_or(phase2_ms);

    let display: Vec<PortEntry> = host
        .ports
        .iter()
        .filter(|p| p.state == "open")
        .map(|p| PortEntry {
            port: p.port,
            protocol: p.protocol.clone(),
            state: p.state.clone(),
            latency_ms: p.rtt_ms.unwrap_or(0.0),
            service: p.service.clone(),
            version: if args.service_version {
                p.version_string.clone()
            } else {
                None
            },
            banner_raw: None,
            confidence: if args.service_version {
                Some("nmap".into())
            } else {
                None
            },
            error: None,
        })
        .collect();

    let ip = host.ip.clone();
    let os = host.os_guess.map(|g| {
        if let Some(acc) = host.os_accuracy {
            format!("{g} ({acc}%)")
        } else {
            g
        }
    });

    if args.json {
        let out = ScanOutput {
            tool: "dxcan-rustscan".into(),
            host: args.host.clone(),
            ip: ip.clone(),
            elapsed_ms: wall_ms,
            scanned: open_ports.len(),
            shown: display.len(),
            results: display,
            os_guess: os,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("dxcan-rustscan scan report for {} ({})", args.host, ip);
        if let Some(ref g) = os {
            println!("OS guess: {g}");
        }
        println!("Scanned {} ports\n", open_ports.len());

        if args.service_version {
            println!(
                "{:<10} {:<10} {:<22} {:<35}",
                "PORT", "STATE", "SERVICE", "VERSION"
            );
            println!("{}", "-".repeat(93));
            for e in &display {
                println!(
                    "{:<10} {:<10} {:<22} {:<35}",
                    format!("{}/{}", e.port, e.protocol),
                    e.state,
                    e.service.as_deref().unwrap_or("unknown"),
                    e.version.as_deref().unwrap_or(""),
                );
            }
        } else {
            println!("{:<10} {:<10} {}", "PORT", "STATE", "SERVICE");
            println!("{}", "-".repeat(50));
            for e in &display {
                println!(
                    "{:<10} {:<10} {}",
                    format!("{}/{}", e.port, e.protocol),
                    e.state,
                    e.service.as_deref().unwrap_or("unknown"),
                );
            }
        }

        println!(
            "\n{} shown — scanned in {}",
            display.len(),
            fmt_duration(wall_ms, args.precise)
        );

        if args.debug {
            println!("\n--- debug ---");
            println!("phase 1 (rustscan): {}", fmt_duration(phase1_ms, true));
            println!(
                "phase 2 (nmap):     {}",
                fmt_duration(nmap_elapsed_ms, true)
            );
            println!(
                "overhead:           {}",
                fmt_duration(phase2_ms - nmap_elapsed_ms, true)
            );
            println!("wall total:         {}", fmt_duration(wall_ms, true));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_rs_config(args: &Args) -> rustscan_runner::RustScanConfig {
    rustscan_runner::RustScanConfig {
        host: args.host.clone(),
        ports: args.ports.clone(),
        batch_size: args.batch_size,
        timeout_ms: args.rs_timeout,
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

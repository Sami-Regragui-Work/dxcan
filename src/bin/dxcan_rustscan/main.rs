//! dxcan-rustscan — RustScan-backed beta of the dxcan port scanner.
//!
//! Two-phase pipeline:
//!   1. RustScan — fast port discovery (finds open ports only)
//!   2. Nmap     — service/version/OS detection on discovered ports only
//!
//! Comparable against dxcan-nmap and dxcan-native on the same host/port inputs.

mod nmap_runner;
mod nmap_xml;
mod output;
mod rustscan_runner;

use clap::Parser;
use output::{PortEntry, ScanOutput};
use std::time::Instant;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dxcan-rustscan",
    about = "dxcan RustScan-backed beta — fast port discovery then Nmap service detection.",
    version
)]
struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    host: String,

    /// Ports: single (22,80), range (1-1024), or - for all 65535
    #[arg(short, long, default_value = "1-65535")]
    ports: String,

    /// Enable OS detection (requires root / CAP_NET_RAW)
    #[arg(long)]
    os: bool,

    /// Enable service/version detection (-sV)
    #[arg(short, long)]
    service: bool,

    /// RustScan batch size — sockets opened per cycle (default: 5000)
    #[arg(long, default_value_t = 5000)]
    batch_size: u16,

    /// RustScan timeout per port in ms (default: 1500)
    #[arg(long, default_value_t = 1500)]
    rs_timeout: u32,

    /// Nmap timing template T0–T5 for the service scan phase (default: 4)
    #[arg(long, default_value_t = 4)]
    timing: u8,

    /// Service version detection intensity 0–9 (default: 5)
    #[arg(long, default_value_t = 5)]
    intensity: u8,

    /// Overall scan timeout in seconds (default: 300)
    #[arg(long, default_value_t = 300)]
    scan_timeout: u64,

    /// Output structured JSON
    #[arg(short, long)]
    json: bool,

    /// Show full latency precision in plain text output
    #[arg(long)]
    precise: bool,

    /// Print the commands that would be run, then exit
    #[arg(long)]
    dry_run: bool,

    /// Pass extra args verbatim to Nmap (after --)
    #[arg(last = true)]
    extra: Vec<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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

    let phase1_elapsed = wall_start.elapsed().as_millis();

    if open_ports.is_empty() {
        if !args.json {
            eprintln!("[dxcan-rustscan] no open ports found");
        }
        // Emit empty result
        let out = ScanOutput {
            tool: "dxcan-rustscan".into(),
            host: args.host.clone(),
            ip: args.host.clone(),
            elapsed_ms: phase1_elapsed as f64,
            scanned: 0,
            shown: 0,
            results: vec![],
            os_guess: None,
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            println!("dxcan-rustscan: no open ports on {}", args.host);
            println!("Phase 1 (discovery): {}ms", phase1_elapsed);
        }
        return;
    }

    if !args.json {
        eprintln!(
            "[dxcan-rustscan] phase 1 done in {}ms — {} open port(s): {}",
            phase1_elapsed,
            open_ports.len(),
            open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        eprintln!("[dxcan-rustscan] phase 2 — service/OS detection via Nmap ...");
    }

    // -----------------------------------------------------------------------
    // Phase 2: Nmap — service + OS detection on open ports only
    // -----------------------------------------------------------------------
    let port_spec = open_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let nmap_cfg = nmap_runner::NmapConfig {
        host: args.host.clone(),
        ports: port_spec,
        service_detection: args.service,
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

    let wall_elapsed = wall_start.elapsed().as_millis() as f64;
    let phase2_elapsed = wall_elapsed - phase1_elapsed as f64;

    // Forward Nmap stderr
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

    let nmap_elapsed_ms = parsed
        .elapsed_secs
        .map(|s| s * 1000.0)
        .unwrap_or(phase2_elapsed);

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
            version: p.version_string.clone(),
            banner_raw: None,
            confidence: Some("nmap".into()),
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
            elapsed_ms: wall_elapsed,
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
        println!("Phase 1 (RustScan discovery): {}ms", phase1_elapsed);
        println!(
            "Phase 2 (Nmap service scan):  {}",
            fmt_duration(nmap_elapsed_ms, args.precise)
        );
        println!(
            "Total wall time:              {}\n",
            fmt_duration(wall_elapsed, args.precise)
        );

        println!(
            "{:<10} {:<10} {:<22} {:<35}",
            "PORT", "STATE", "SERVICE", "VERSION"
        );
        println!("{}", "-".repeat(80));

        for e in &display {
            println!(
                "{:<10} {:<10} {:<22} {:<35}",
                format!("{}/{}", e.port, e.protocol),
                e.state,
                e.service.as_deref().unwrap_or("unknown"),
                e.version.as_deref().unwrap_or(""),
            );
        }

        println!("\n{} ports shown", display.len());
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

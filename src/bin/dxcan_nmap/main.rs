//! dxcan-nmap — Nmap-backed beta of the dxcan port scanner.
//!
//! Wraps Nmap cleanly: builds args, runs the process, parses XML output,
//! and emits dxcan's standard JSON or plain-text format.
//! Comparable against dxcan-native on the same host/port inputs.

mod nmap_runner;
mod nmap_xml;
mod output;

use clap::Parser;
use output::{PortEntry, ScanOutput};
use std::time::Instant;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dxcan-nmap",
    about = "dxcan Nmap-backed beta — wraps Nmap, emits dxcan JSON/text output.",
    version
)]
struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    host: String,

    /// Ports: single (22,80), range (1-1024), mixed (22,8000-9000), or - for all
    #[arg(short, long, default_value = "1-65535")]
    ports: String,

    /// Enable OS detection (requires root / CAP_NET_RAW)
    #[arg(long)]
    os: bool,

    /// Nmap timing template T0–T5 (default: 4)
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

    /// Show closed and filtered ports too (default: open only)
    #[arg(long)]
    all: bool,

    /// Print the Nmap command that would be run, then exit
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
        let cfg = build_config(&args);
        let nmap_args = nmap_runner::build_args(&cfg);
        println!("nmap {}", nmap_args.join(" "));
        return;
    }

    // --- check nmap is available ---
    match nmap_runner::check_nmap().await {
        Ok(v)  => eprintln!("[dxcan-nmap] using {v}"),
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    }

    let cfg      = build_config(&args);
    let wall_start = Instant::now();

    if !args.json {
        eprintln!(
            "[dxcan-nmap] scanning {} on ports {} ...",
            args.host, args.ports
        );
    }

    // --- run nmap ---
    let raw = match nmap_runner::run(&cfg).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };

    let wall_elapsed = wall_start.elapsed().as_millis() as f64;

    // Forward nmap stderr if it has anything useful
    if !raw.stderr.is_empty() {
        for line in raw.stderr.lines() {
            // Skip the "Starting Nmap" banner and progress lines to keep stderr clean
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
        eprintln!("[error] Nmap produced no XML output (exit code {})", raw.exit_code);
        if raw.exit_code == 1 {
            eprintln!("[hint] OS detection (-O / --os) requires root or CAP_NET_RAW.");
        }
        std::process::exit(1);
    }

    // --- parse XML ---
    let parsed = match nmap_xml::parse(&raw.xml) {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("[error] XML parse failed: {e}");
            std::process::exit(1);
        }
    };

    // --- we target a single host ---
    let host = match parsed.hosts.into_iter().next() {
        Some(h) => h,
        None => {
            eprintln!("[error] No host results in Nmap output. Host may be down.");
            std::process::exit(1);
        }
    };

    // Nmap's own elapsed in ms (falls back to wall clock)
    let elapsed_ms = parsed
        .elapsed_secs
        .map(|s| s * 1000.0)
        .unwrap_or(wall_elapsed);

    // --- build display entries ---
    let all_ports = &host.ports;
    let display: Vec<PortEntry> = all_ports
        .iter()
        .filter(|p| args.all || p.state == "open")
        .map(|p| PortEntry {
            port:       p.port,
            protocol:   p.protocol.clone(),
            state:      p.state.clone(),
            latency_ms: p.rtt_ms.unwrap_or(0.0),
            service:    p.service.clone(),
            version:    p.version_string.clone(),
            banner_raw: None, // Nmap XML doesn't expose raw banners
            confidence: Some("nmap".into()),
            error:      None,
        })
        .collect();

    let scanned = all_ports.len();
    let shown   = display.len();
    let ip      = host.ip.clone();
    let os      = host.os_guess.map(|g| {
        if let Some(acc) = host.os_accuracy {
            format!("{g} ({acc}%)")
        } else {
            g
        }
    });

    // --- output ---
    if args.json {
        let out = ScanOutput {
            tool:       "dxcan-nmap".into(),
            host:       args.host.clone(),
            ip:         ip.clone(),
            elapsed_ms,
            scanned,
            shown,
            results:    display,
            os_guess:   os,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("dxcan-nmap scan report for {} ({})", args.host, ip);
        if let Some(ref g) = os {
            println!("OS guess: {g}");
        }
        println!(
            "Nmap scanned {} ports in {}\n",
            scanned,
            fmt_duration(elapsed_ms, args.precise)
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

        println!("\n{shown} ports shown");
        println!("Wall time: {}", fmt_duration(wall_elapsed, args.precise));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_config(args: &Args) -> nmap_runner::NmapConfig {
    nmap_runner::NmapConfig {
        host:              args.host.clone(),
        ports:             args.ports.clone(),
        service_detection: true,
        os_detection:      args.os,
        version_intensity: args.intensity,
        scan_timeout:      std::time::Duration::from_secs(args.scan_timeout),
        timing:            args.timing,
        extra_args:        args.extra.clone(),
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
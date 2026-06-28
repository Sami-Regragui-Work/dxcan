mod cli;
mod display;
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
use display::{print_open_ports_summary, print_os_details, print_port_table, DisplayOpts};
use output::{PortEntry, ScanOutput};
use resolver::{resolve_host, reverse_dns};
use scanners::network::port::PortResult;
use scanners::network::{
    os::detect_os,
    port::{parse_ports, scan_port},
    rtt::RttTracker,
    service::{port_label, service_role_label, ServiceProber},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let t0 = Instant::now();

    let args = Args::parse();
    let service_version = args.service_version || args.rich;
    let do_reverse_dns = args.reverse_dns || args.rich;
    let role_labels = args.role_labels || args.rich;

    let ip = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };

    let reverse_name = if do_reverse_dns {
        reverse_dns(ip).await
    } else {
        None
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

    let max_rtt_ms = open_ports
        .iter()
        .map(|r| r.latency_ms)
        .fold(0.0_f64, f64::max);

    let service_ms;
    let service_passive_ms = ((max_rtt_ms * 10.0).max(20.0).min(500.0)) as u64;
    let service_active_ms = service_passive_ms;

    struct ServiceInfo {
        service: String,
        version: Option<String>,
        banner_raw: Option<String>,
        confidence: Option<String>,
        role: Option<String>,
        detection_ms: f64,
    }

    let services: HashMap<u16, ServiceInfo> = if service_version {
        let service_start = Instant::now();
        let prober = ServiceProber::new(service_passive_ms, service_active_ms);

        let mut sfuts = FuturesUnordered::new();
        for r in &open_ports {
            sfuts.push(prober.probe(ip, r.port));
        }

        let mut map = HashMap::new();
        while let Some(s) = sfuts.next().await {
            let role = if role_labels {
                service_role_label(&s.service).map(str::to_string)
            } else {
                None
            };
            map.insert(
                s.port,
                ServiceInfo {
                    service: s.service,
                    version: s.version,
                    banner_raw: s.banner_raw,
                    confidence: Some(s.confidence.to_string()),
                    role,
                    detection_ms: s.detection_ms,
                },
            );
        }
        service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
        map
    } else {
        service_ms = 0.0;
        open_ports
            .iter()
            .map(|r| {
                let name = port_label(r.port).unwrap_or("unknown").to_string();
                let role = if role_labels {
                    service_role_label(&name).map(str::to_string)
                } else {
                    None
                };
                (
                    r.port,
                    ServiceInfo {
                        service: name,
                        version: None,
                        banner_raw: None,
                        confidence: None,
                        role,
                        detection_ms: 0.0,
                    },
                )
            })
            .collect()
    };

    let open_port_nums: Vec<u16> = open_ports.iter().map(|r| r.port).collect();

    let os_ms;
    let os_guess;
    let os_accuracy;
    let os_details;
    if args.os_detect {
        let os_timeout = ((max_rtt_ms * 20.0).max(500.0).min(3000.0)) as u64;
        match detect_os(ip, &open_port_nums, os_timeout) {
            Ok(r) => {
                os_ms = r.detection_ms;
                os_guess = r.guess;
                os_accuracy = r.accuracy;
                os_details = r.details;
            }
            Err(e) => {
                eprintln!("[error] {e}");
                std::process::exit(1);
            }
        }
    } else {
        os_ms = 0.0;
        os_guess = None;
        os_accuracy = None;
        os_details = Default::default();
    }

    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;

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
                version: if service_version {
                    svc.and_then(|s| s.version.clone())
                } else {
                    None
                },
                banner_raw: if service_version {
                    svc.and_then(|s| s.banner_raw.clone())
                } else {
                    None
                },
                confidence: if service_version {
                    svc.and_then(|s| s.confidence.clone())
                } else {
                    None
                },
                role: svc.and_then(|s| s.role.clone()),
                error: r.error.clone(),
            }
        })
        .collect();

    let open_entries: Vec<&PortEntry> = display.iter().filter(|e| e.state == "open").collect();
    let mut info_level = compute_info_level(&open_entries, reverse_name.is_some());
    if os_guess.is_some() {
        info_level += 1;
        if os_accuracy.is_some_and(|a| a >= 90) {
            info_level += 1;
        }
        if os_details.device_type.is_some() || !os_details.cpes.is_empty() {
            info_level += 1;
        }
    }

    let os_label = os_guess
        .as_deref()
        .unwrap_or("no match");

    if args.json {
        let (json_os_guess, json_os_accuracy, json_os_details) = if args.os_detect {
            (
                Some(os_label.to_string()),
                os_accuracy,
                Some(&os_details),
            )
        } else {
            (None, None, None)
        };
        let output = ScanOutput {
            tool: "dxcan".into(),
            host: args.host.clone(),
            ip: ip.to_string(),
            reverse_dns: reverse_name.clone(),
            elapsed_ms: wall_ms,
            scanned: total,
            shown: display.len(),
            results: display,
            info_level,
            os_guess: json_os_guess,
            os_accuracy: json_os_accuracy,
            os_vendor: json_os_details.and_then(|d| d.vendor.clone()),
            os_family: json_os_details.and_then(|d| d.os_family.clone()),
            os_gen: json_os_details.and_then(|d| d.os_gen.clone()),
            os_device_type: json_os_details.and_then(|d| d.device_type.clone()),
            os_running: json_os_details.and_then(|d| d.running.clone()),
            os_cpes: json_os_details.map(|d| d.cpes.clone()).unwrap_or_default(),
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        if args.host != ip.to_string() {
            println!("dxcan scan report for {} ({})", args.host, ip);
        } else {
            println!("dxcan scan report for {}", args.host);
        }
        if let Some(ref name) = reverse_name {
            println!("Reverse-DNS: {name}");
        }
        println!("Scanned {total} ports\n");

        let table_opts = DisplayOpts {
            service_version,
            role_labels,
            precise: args.precise,
            os: if args.os_detect {
                Some((os_label.to_string(), os_accuracy))
            } else {
                None
            },
        };
        print_port_table(&display, &table_opts);

        if args.os_detect && os_guess.is_some() {
            print_os_details(os_label, os_accuracy, &os_details);
        }

        if args.all {
            print_open_ports_summary(&display);
        }

        println!(
            "\n{} shown — scanned in {} (info_level={info_level})",
            display.len(),
            display::fmt_duration(wall_ms, args.precise)
        );

        if args.debug {
            println!("\n--- debug ---");
            println!("connect total:   {}", display::fmt_duration(scan_ms, true));
            if service_version {
                println!(
                    "service total:   {}",
                    display::fmt_duration(service_ms, true)
                );
                println!(
                    "service timeout: passive={}ms  active={}ms  (derived from max RTT {:.2}ms)",
                    service_passive_ms, service_active_ms, max_rtt_ms
                );
            }
            if args.os_detect {
                println!("os total:        {}", display::fmt_duration(os_ms, true));
            }
            println!("wall total:      {}", display::fmt_duration(wall_ms, true));
        }
    }
}

fn compute_info_level(open_entries: &[&PortEntry], has_reverse_dns: bool) -> u32 {
    let mut info_level = open_entries.len() as u32;
    if has_reverse_dns {
        info_level += 1;
    }
    for e in open_entries {
        if e.version.is_some() {
            info_level += 1;
        } else if e.banner_raw.is_some() {
            info_level += 1;
        }
        if e.role.is_some() {
            info_level += 1;
        } else if e.service.as_deref().is_some_and(|s| s != "unknown") {
            info_level += 1;
        }
    }
    info_level
}

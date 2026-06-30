mod cli;
mod display;
mod output;
mod resolver;
mod scanners;

use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::time::Instant;

use cli::Args;
use display::{
    print_domain_results, print_open_ports_summary, print_os_details, print_port_table,
    print_vhost_results, DisplayOpts,
};
use output::{DomainEntry, PortEntry, ScanOutput, VhostEntry};
use resolver::{resolve_host, reverse_dns};
use scanners::network::port::{parse_ports, run_port_scan, scan_mode, PortResult, ScanPlan};
use scanners::network::{
    domain::{discover_domains, normalize_apex, DomainOptions},
    os::detect_os,
    service::{port_label, product_hint_from_banner, service_role_label, ServiceProber},
    vhost::{discover_vhosts, parse_status_list, parse_usize_list, pick_http_ports, resolve_base_domain, VhostOptions},
};

struct ServiceInfo {
    service: String,
    version: Option<String>,
    banner_raw: Option<String>,
    confidence: Option<String>,
    role: Option<String>,
    detection_ms: f64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let t0 = Instant::now();

    let args = Args::parse();
    if args.domain && args.vhost {
        eprintln!("[error] --domain and --vhost are mutually exclusive");
        std::process::exit(1);
    }
    if args.domain {
        run_domain_only(&args).await;
        return;
    }
    if args.product_hints && !args.os_detect && !args.os_rich {
        eprintln!("[error] --product-hints requires --os (or use --os-rich)");
        std::process::exit(1);
    }
    let os_detect = args.os_detect || args.os_rich;
    let product_hints = args.product_hints || args.os_rich;
    let service_version = args.service_version || args.sv_rich;
    let do_reverse_dns = args.reverse_dns || args.sv_rich;
    let role_labels = args.role_labels || args.sv_rich;

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
    let mode = scan_mode(args.all);
    let plan = ScanPlan {
        mode,
        method: args.scan_method,
        verify: args.verify,
        reliable_opens: os_detect,
    };

    let scan_start = Instant::now();
    let scan_outcome = match run_port_scan(ip, &ports, args.timeout, args.workers, &plan).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };
    let results = scan_outcome.results;
    let closed_port_nums = scan_outcome.closed_samples;
    let max_rtt_ms = scan_outcome.max_rtt_ms;
    let scan_method_label = scan_outcome.method_label;
    let scan_ms = scan_start.elapsed().as_secs_f64() * 1000.0;

    let open_ports: Vec<&PortResult> = results.iter().filter(|r| r.state == "open").collect();

    let service_ms;
    let (service_passive_ms, service_active_ms) = service_probe_timeouts(max_rtt_ms, args.timeout);
    let probe_services = service_version || product_hints;

    let services: HashMap<u16, ServiceInfo> = if probe_services && !open_ports.is_empty() {
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
    let mut os_details;
    if os_detect {
        let os_timeout = ((max_rtt_ms * 20.0).max(500.0).min(3000.0)) as u64;
        match detect_os(
            ip,
            &open_port_nums,
            &closed_port_nums,
            max_rtt_ms,
            os_timeout,
        ) {
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
        if product_hints {
            os_details.product_hints = collect_product_hints(&services);
        }
    } else {
        os_ms = 0.0;
        os_guess = None;
        os_accuracy = None;
        os_details = Default::default();
    }

    let mut vhost_ms = 0.0;
    let mut vhost_entries: Vec<VhostEntry> = Vec::new();
    let mut vhost_probed = 0usize;
    let mut vhost_scan_port: Option<u16> = None;
    let mut vhost_baseline_status = 0u16;
    let mut vhost_baseline_len = 0usize;
    let mut vhost_baseline_hash = String::new();
    let mut vhost_baseline_lines = 0usize;
    let mut vhost_baseline_words = 0usize;
    let mut vhost_tls = false;

    if args.vhost {
        let http_ports = pick_http_ports(&open_port_nums, args.vhost_port);
        if http_ports.is_empty() {
            eprintln!("[error] --vhost: no open HTTP ports (try -p 80 or --vhost-port)");
            std::process::exit(1);
        }
        let base_domain = args
            .vhost_domain
            .clone()
            .unwrap_or_else(|| resolve_base_domain(&args.host, reverse_name.as_deref()));
        let wordlist_path = args.vhost_wordlist.as_ref().map(std::path::PathBuf::from);
        let vhost_workers = args
            .vhost_workers
            .unwrap_or_else(|| args.workers.max(50).min(200));
        let request_timeout = std::time::Duration::from_secs_f64(args.timeout.max(2.0));
        let ignore_lengths = args
            .vhost_ignore_length
            .as_deref()
            .map(parse_usize_list)
            .unwrap_or_default();
        let ignore_statuses = args
            .vhost_ignore_status
            .as_deref()
            .map(parse_status_list)
            .unwrap_or_default();

        for port in http_ports {
            let opts = VhostOptions {
                ip,
                port,
                base_domain: base_domain.clone(),
                wordlist_path: wordlist_path.clone(),
                path: args.vhost_path.clone(),
                workers: vhost_workers,
                request_timeout,
                calibrate: args.vhost_calibrate,
                tls: args.vhost_tls,
                match_hash: args.vhost_hash,
                length_margin: args.vhost_length_margin,
                ignore_lengths: ignore_lengths.clone(),
                ignore_statuses: ignore_statuses.clone(),
                dev: args.dev,
            };
            match discover_vhosts(&opts).await {
                Ok(r) => {
                    vhost_ms += r.detection_ms;
                    vhost_tls = r.tls;
                    vhost_probed += r.probed;
                    vhost_scan_port = Some(r.port);
                    vhost_baseline_status = r.baseline.status;
                    vhost_baseline_len = r.baseline.body_len;
                    vhost_baseline_hash = scanners::network::vhost::body_hash_hex(r.baseline.body_hash);
                    vhost_baseline_lines = r.baseline.body_lines;
                    vhost_baseline_words = r.baseline.body_words;
                    for hit in r.hits {
                        vhost_entries.push(VhostEntry {
                            hostname: hit.hostname,
                            port: hit.port,
                            status: hit.status,
                            body_len: hit.body_len,
                            body_lines: hit.body_lines,
                            body_words: hit.body_words,
                            location: hit.location,
                            body_hash: hit.body_hash,
                            latency_ms: hit.latency_ms,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("[error] vhost on port {port}: {e}");
                    std::process::exit(1);
                }
            }
        }
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
        if product_hints && !os_details.product_hints.is_empty() {
            info_level += 1;
        }
    }
    if !vhost_entries.is_empty() {
        info_level += vhost_entries.len() as u32;
    }

    let os_label = os_guess.as_deref().unwrap_or("no match");

    if args.json {
        let (json_os_guess, json_os_accuracy, json_os_details) = if os_detect {
            (Some(os_label.to_string()), os_accuracy, Some(&os_details))
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
            vhosts: vhost_entries.clone(),
            vhost_probed: if args.vhost { Some(vhost_probed) } else { None },
            vhost_port: if args.vhost { vhost_scan_port } else { None },
            vhost_tls: if args.vhost { Some(vhost_tls) } else { None },
            vhost_elapsed_ms: if args.vhost { Some(vhost_ms) } else { None },
            vhost_baseline_hash: if args.vhost && !vhost_baseline_hash.is_empty() {
                Some(vhost_baseline_hash.clone())
            } else {
                None
            },
            vhost_baseline_lines: if args.vhost {
                Some(vhost_baseline_lines)
            } else {
                None
            },
            vhost_baseline_words: if args.vhost {
                Some(vhost_baseline_words)
            } else {
                None
            },
            domains: Vec::new(),
            domain_probed: None,
            domain_elapsed_ms: None,
            domain_wildcard_ips: Vec::new(),
            domain_resolver_source: None,
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
            domain_rich: false,
        };
        print_port_table(&display, &table_opts);

        if os_detect && os_guess.is_some() {
            print_os_details(os_label, os_accuracy, &os_details);
        }

        if args.vhost {
            let vport = vhost_scan_port.unwrap_or(0);
            print_vhost_results(
                &vhost_entries,
                vport,
                vhost_probed,
                vhost_baseline_status,
                vhost_baseline_len,
                &table_opts,
            );
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
            println!("port scan:       {}", display::fmt_duration(scan_ms, true));
            println!("scan method:     {scan_method_label}");
            if args.verify {
                println!("verify:          connect confirm on opens");
            }
            if probe_services {
                println!(
                    "service total:   {}",
                    display::fmt_duration(service_ms, true)
                );
                println!(
                    "service timeout: passive={}ms  active={}ms  (derived from max RTT {:.2}ms)",
                    service_passive_ms, service_active_ms, max_rtt_ms
                );
            }
            if os_detect {
                println!("os total:        {}", display::fmt_duration(os_ms, true));
            }
            if args.vhost {
                println!("vhost total:     {}", display::fmt_duration(vhost_ms, true));
                println!("vhost probed:    {vhost_probed}");
                println!("vhost found:     {}", vhost_entries.len());
                println!("vhost tls:       {vhost_tls}");
            }
            println!("wall total:      {}", display::fmt_duration(wall_ms, true));
        }
    }
}

fn service_probe_timeouts(max_rtt_ms: f64, scan_timeout_secs: f64) -> (u64, u64) {
    let floor_ms = (scan_timeout_secs * 1000.0 * 3.0).max(1500.0);
    let active = (max_rtt_ms * 15.0).max(floor_ms).min(8000.0) as u64;
    let passive = ((active as f64) * 0.6).max(300.0).min(4000.0) as u64;
    (passive, active)
}

fn collect_product_hints(services: &HashMap<u16, ServiceInfo>) -> Vec<String> {
    let mut hints = Vec::new();
    for (port, svc) in services {
        let text = svc
            .version
            .as_deref()
            .or(svc.banner_raw.as_deref())
            .unwrap_or("");
        if let Some(hint) = product_hint_from_banner(*port, text) {
            hints.push(hint);
        }
    }
    hints.sort_unstable();
    hints
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

async fn run_domain_only(args: &Args) {
    let t0 = Instant::now();
    let apex = normalize_apex(&args.host);
    let wordlist_path = args.domain_wordlist.as_ref().map(std::path::PathBuf::from);
    let resolvers_path = args.domain_resolvers.as_ref().map(std::path::PathBuf::from);
    let workers = args
        .domain_workers
        .unwrap_or_else(|| args.workers.max(50).min(500));
    let query_secs = args
        .domain_query_timeout
        .unwrap_or_else(|| args.timeout.min(1.0).max(0.5));
    let query_timeout = std::time::Duration::from_secs_f64(query_secs);
    let query_aaaa = args.domain_aaaa || args.domain_rich;
    let show_cname = args.domain_rich;
    let show_ttl = args.domain_rich;
    let opts = DomainOptions {
        apex: apex.clone(),
        wordlist_path,
        resolvers_path,
        workers,
        query_timeout,
        wildcard_samples: args.domain_wildcard_samples,
        filter_wildcard: !args.domain_no_wildcard_filter,
        query_aaaa,
        show_cname,
        show_ttl,
        dev: args.dev,
        max_inflight: args.domain_max_inflight,
    };

    let result = match discover_domains(&opts).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] domain discovery: {e}");
            std::process::exit(1);
        }
    };

    let domain_entries: Vec<DomainEntry> = result
        .hits
        .iter()
        .map(|h| DomainEntry {
            fqdn: h.fqdn.clone(),
            ips: h.ips.clone(),
            latency_ms: h.latency_ms,
            aaaa: h.aaaa.clone(),
            cname: h.cname.clone(),
            ttl: h.ttl,
        })
        .collect();

    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let mut info_level = domain_entries.len() as u32;
    for e in &domain_entries {
        info_level += e.ips.len() as u32;
        info_level += e.aaaa.len() as u32;
        if e.cname.is_some() {
            info_level += 1;
        }
        if e.ttl.is_some() {
            info_level += 1;
        }
    }

    if args.json {
        let output = ScanOutput {
            tool: "dxcan".into(),
            host: args.host.clone(),
            ip: String::new(),
            reverse_dns: None,
            elapsed_ms: wall_ms,
            scanned: 0,
            shown: 0,
            results: Vec::new(),
            info_level,
            os_guess: None,
            os_accuracy: None,
            os_vendor: None,
            os_family: None,
            os_gen: None,
            os_device_type: None,
            os_running: None,
            os_cpes: Vec::new(),
            vhosts: Vec::new(),
            vhost_probed: None,
            vhost_port: None,
            vhost_tls: None,
            vhost_elapsed_ms: None,
            vhost_baseline_hash: None,
            vhost_baseline_lines: None,
            vhost_baseline_words: None,
            domains: domain_entries.clone(),
            domain_probed: Some(result.probed),
            domain_elapsed_ms: Some(result.detection_ms),
            domain_wildcard_ips: result.wildcard_ips.clone(),
            domain_resolver_source: Some(result.resolver_source.clone()),
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("dxcan domain discovery for {apex}");
    let table_opts = DisplayOpts {
        service_version: false,
        role_labels: false,
        precise: args.precise,
        domain_rich: args.domain_rich,
    };
    print_domain_results(
        &domain_entries,
        &apex,
        result.probed,
        &result.wildcard_ips,
        &table_opts,
    );
    println!(
        "\n{} subdomain(s) — scanned in {} (info_level={info_level})",
        domain_entries.len(),
        display::fmt_duration(wall_ms, args.precise)
    );
    if args.debug {
        println!("\n--- debug ---");
        println!("domain resolvers: {}", result.resolver_source);
        if let Some(limit) = args.domain_max_inflight {
            println!("domain max_inflight: {limit}");
        }
        println!(
            "domain total:    {}",
            display::fmt_duration(result.detection_ms, true)
        );
        println!("domain probed:   {}", result.probed);
        println!("domain found:    {}", domain_entries.len());
        println!("domain workers:  {workers}");
        println!("wall total:      {}", display::fmt_duration(wall_ms, true));
    }
}

use crate::output::{PortEntry, VhostEntry};

pub struct DisplayOpts {
    pub service_version: bool,
    pub role_labels: bool,
    pub precise: bool,
}

pub fn print_port_table(entries: &[PortEntry], opts: &DisplayOpts) {
    let mut cols: Vec<(&str, usize)> = vec![
        ("PORT", 10),
        ("STATE", 10),
        ("LATENCY", 13),
        ("SERVICE", 12),
    ];
    if opts.service_version {
        let version_w = entries
            .iter()
            .map(|e| e.version.as_deref().unwrap_or("").len())
            .max()
            .unwrap_or(0)
            .max("VERSION".len())
            .min(80);
        cols.push(("VERSION", version_w));
    }
    if opts.role_labels {
        let role_w = entries
            .iter()
            .map(|e| e.role.as_deref().unwrap_or("").len())
            .max()
            .unwrap_or(0)
            .max("ROLE".len())
            .min(80);
        cols.push(("ROLE", role_w));
    }
    if opts.service_version {
        cols.push(("CONFIDENCE", 12));
    }

    let header: String = cols
        .iter()
        .map(|(name, w)| format!("{name:<w$}"))
        .collect::<Vec<_>>()
        .join(" ");
    let width: usize = cols.iter().map(|(_, w)| *w).sum::<usize>() + cols.len().saturating_sub(1);
    println!("{header}");
    println!("{}", "-".repeat(width));

    for e in entries {
        let mut fields: Vec<String> = vec![
            format!("{}/{}", e.port, e.protocol),
            e.state.clone(),
            fmt_duration(e.latency_ms, opts.precise),
            e.service.as_deref().unwrap_or("unknown").to_string(),
        ];
        if opts.service_version {
            fields.push(e.version.as_deref().unwrap_or("").to_string());
        }
        if opts.role_labels {
            fields.push(e.role.as_deref().unwrap_or("").to_string());
        }
        if opts.service_version {
            fields.push(e.confidence.as_deref().unwrap_or("").to_string());
        }

        let row: String = fields
            .iter()
            .zip(cols.iter())
            .map(|(val, (_, w))| truncate_pad(val, *w))
            .collect::<Vec<_>>()
            .join(" ");
        println!("{row}");
    }
}

pub fn print_vhost_results(
    hits: &[VhostEntry],
    port: u16,
    probed: usize,
    baseline_status: u16,
    baseline_len: usize,
    opts: &DisplayOpts,
) {
    println!();
    println!("Virtual hosts on port {port} (baseline {baseline_status}/{baseline_len} bytes, probed {probed}):");
    if hits.is_empty() {
        println!("  (none)");
        return;
    }
    let cols: [(&str, usize); 4] = [
        ("HOST", 40),
        ("STATUS", 8),
        ("LENGTH", 10),
        ("LATENCY", 13),
    ];
    let header: String = cols
        .iter()
        .map(|(name, w)| format!("{name:<w$}"))
        .collect::<Vec<_>>()
        .join(" ");
    let width: usize = cols.iter().map(|(_, w)| *w).sum::<usize>() + cols.len().saturating_sub(1);
    println!("{header}");
    println!("{}", "-".repeat(width));
    for h in hits {
        let row = [
            truncate_pad(&h.hostname, cols[0].1),
            truncate_pad(&h.status.to_string(), cols[1].1),
            truncate_pad(&h.body_len.to_string(), cols[2].1),
            truncate_pad(&fmt_duration(h.latency_ms, opts.precise), cols[3].1),
        ]
        .join(" ");
        println!("{row}");
    }
}

use crate::scanners::network::os::OsMatchDetails;

pub fn print_os_details(guess: &str, accuracy: Option<u8>, details: &OsMatchDetails) {
    println!();
    if let Some(device) = &details.device_type {
        println!("Device type: {device}");
    }
    if let Some(running) = details.nmap_running_line() {
        println!("Running: {running}");
    }
    for cpe in &details.cpes {
        println!("OS CPE: {cpe}");
    }
    println!("OS details: {guess}");
    if let Some(a) = accuracy {
        println!("OS match accuracy: {a}%");
    }
    for hint in &details.product_hints {
        println!("Product hint: {hint}");
    }
}

pub fn print_open_ports_summary(entries: &[PortEntry]) {
    let open: Vec<String> = entries
        .iter()
        .filter(|e| e.state == "open")
        .map(|e| e.port.to_string())
        .collect();
    if open.is_empty() {
        return;
    }
    println!(
        "\nOpen TCP ports ({}): {}",
        open.len(),
        open.join(", ")
    );
}

fn truncate_pad(s: &str, width: usize) -> String {
    if s.len() <= width {
        format!("{s:<width$}")
    } else if width > 1 {
        format!("{}…", &s[..width.saturating_sub(1)])
    } else {
        s.chars().take(width).collect()
    }
}

pub fn fmt_duration(ms: f64, precise: bool) -> String {
    if precise {
        format!("{ms:.3}ms")
    } else if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else {
        format!("{ms:.1}ms")
    }
}

use crate::output::PortEntry;

pub struct DisplayOpts {
    pub service_version: bool,
    pub role_labels: bool,
    pub precise: bool,
    pub os: Option<(String, Option<u8>)>,
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
    let os_acc_str = opts
        .os
        .as_ref()
        .and_then(|(_, acc)| acc.map(|a| format!("{a}%")))
        .unwrap_or_else(|| "—".to_string());
    if opts.os.is_some() {
        let os_w = opts
            .os
            .as_ref()
            .map(|(g, _)| g.len())
            .unwrap_or(0)
            .max("OS".len())
            .min(80);
        cols.push(("OS", os_w));
        cols.push(("ACCURACY", os_acc_str.len().max("ACCURACY".len()).max(8)));
    }

    let os_row = opts
        .os
        .as_ref()
        .and_then(|_| entries.iter().position(|e| e.state == "open"));

    let header: String = cols
        .iter()
        .map(|(name, w)| format!("{name:<w$}"))
        .collect::<Vec<_>>()
        .join(" ");
    let width: usize = cols.iter().map(|(_, w)| *w).sum::<usize>() + cols.len().saturating_sub(1);
    println!("{header}");
    println!("{}", "-".repeat(width));

    for (idx, e) in entries.iter().enumerate() {
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
        if opts.os.is_some() {
            if os_row == Some(idx) {
                let (guess, accuracy) = opts.os.as_ref().unwrap();
                fields.push(guess.clone());
                fields.push(
                    accuracy
                        .map(|a| format!("{a}%"))
                        .unwrap_or_else(|| "—".to_string()),
                );
            } else {
                fields.push(String::new());
                fields.push(String::new());
            }
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

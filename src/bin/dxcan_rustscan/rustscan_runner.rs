//! RustScan subprocess runner.
//!
//! Handles phase 1: fast port discovery.
//! Returns a sorted list of open port numbers — nothing more.
//! Phase 2 (service/OS detection) is handled by nmap_runner.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RustScanConfig {
    /// Target host (IP or hostname)
    pub host: String,
    /// Port spec: "1-65535" (range) or "22,80,443" (comma list)
    pub ports: String,
    /// Sockets opened per batch cycle (default: 5000)
    pub batch_size: u16,
    /// Per-port timeout in milliseconds (default: 1500)
    pub timeout_ms: u32,
}

impl Default for RustScanConfig {
    fn default() -> Self {
        Self {
            host:       String::new(),
            ports:      "1-65535".into(),
            batch_size: 5000,
            timeout_ms: 1500,
        }
    }
}

// ---------------------------------------------------------------------------
// Port spec helpers
// ---------------------------------------------------------------------------

/// Return true if the port spec is a range (contains '-' and no ',').
/// "1-1024"   → range  → use --range
/// "22,80,443" → list  → use --ports
/// "1-65535"  → range  → use --range
fn is_range(ports: &str) -> bool {
    ports.contains('-') && !ports.contains(',')
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Check that `rustscan` is on PATH and return its version string.
pub async fn check_rustscan() -> Result<String, String> {
    let out = Command::new("rustscan")
        .arg("--version")
        .output()
        .await
        .map_err(|e| format!("rustscan not found or not executable: {e}"))?;
    let ver = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("unknown")
        .to_string();
    Ok(ver)
}

/// Build the RustScan argument list. Exported for dry-run display.
///
/// Key flags for 2.4.1:
///   --greppable   → skips Nmap entirely, outputs "Open IP:PORT" lines
///   --range       → accepts "start-end" format
///   --ports / -p  → accepts comma-separated list
///   --no-banner   → suppresses the ASCII art banner on stderr
pub fn build_args(cfg: &RustScanConfig) -> Vec<String> {
    let mut args: Vec<String> = vec![
        // Target
        "-a".into(), cfg.host.clone(),
        // Batch size
        "-b".into(), cfg.batch_size.to_string(),
        // Per-port timeout
        "--timeout".into(), cfg.timeout_ms.to_string(),
        // Greppable = no Nmap, output only "Open IP:PORT" lines
        "--greppable".into(),
        // Suppress banner so stderr is clean
        "--no-banner".into(),
    ];

    // --range for "1-1024" style, --ports for "22,80,631" style
    if is_range(&cfg.ports) {
        args.push("--range".into());
        args.push(cfg.ports.clone());
    } else {
        args.push("--ports".into());
        args.push(cfg.ports.clone());
    }

    args
}

/// Run RustScan and return sorted list of open port numbers.
///
/// RustScan 2.4.1 greppable output:
///   127.0.0.1 -> [22,80,631]        ← summary line (stdout)
///   Open 127.0.0.1:22               ← one line per open port (stdout)
///   Open 127.0.0.1:80
///   Open 127.0.0.1:631
///
/// We parse both formats so we're robust to minor version differences.
pub async fn run(cfg: &RustScanConfig, scan_timeout: Duration) -> Result<Vec<u16>, String> {
    let args = build_args(cfg);

    let mut child = Command::new("rustscan")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn rustscan: {e}. Is rustscan installed?"))?;

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let (stdout_raw, _stderr_raw) = timeout(scan_timeout, async {
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut h) = stdout_handle {
            h.read_to_string(&mut out).await.ok();
        }
        if let Some(mut h) = stderr_handle {
            h.read_to_string(&mut err).await.ok();
        }
        (out, err)
    })
    .await
    .map_err(|_| format!("RustScan timed out after {scan_timeout:?}"))?;

    child
        .wait()
        .await
        .map_err(|e| format!("Failed to wait for rustscan: {e}"))?;

    let ports = parse_output(&stdout_raw);
    Ok(ports)
}

// ---------------------------------------------------------------------------
// Output parser
// ---------------------------------------------------------------------------

/// Parse RustScan 2.4.1 greppable output into a sorted, deduplicated port list.
///
/// Handles three observed formats:
///
///   Format A  — summary line:
///     "127.0.0.1 -> [22,80,631]"
///
///   Format B  — one line per port:
///     "Open 127.0.0.1:22"
///
///   Format C  — old greppable (pre-2.x):
///     "Host: 127.0.0.1 ()    Ports: 22/open/tcp/////"
fn parse_output(output: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Format A: "X.X.X.X -> [22,80,631]"
        if let Some(bracket) = line.find("-> [") {
            let inner = &line[bracket + 4..];
            if let Some(close) = inner.find(']') {
                for p in inner[..close].split(',') {
                    if let Ok(n) = p.trim().parse::<u16>() {
                        if n > 0 { ports.push(n); }
                    }
                }
            }
            continue;
        }

        // Format B: "Open X.X.X.X:PORT"
        if line.starts_with("Open ") {
            if let Some(colon) = line.rfind(':') {
                if let Ok(n) = line[colon + 1..].trim().parse::<u16>() {
                    if n > 0 { ports.push(n); }
                }
            }
            continue;
        }

        // Format C: "Host: X.X.X.X ()    Ports: 22/open/tcp/////, ..."
        if line.starts_with("Host:") {
            if let Some(ports_part) = line.split("Ports:").nth(1) {
                for entry in ports_part.split(',') {
                    if let Some(port_str) = entry.trim().split('/').next() {
                        if let Ok(n) = port_str.trim().parse::<u16>() {
                            if n > 0 { ports.push(n); }
                        }
                    }
                }
            }
        }
    }

    ports.sort_unstable();
    ports.dedup();
    ports
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_format_a_summary() {
        let output = "127.0.0.1 -> [22,80,631]";
        assert_eq!(parse_output(output), vec![22, 80, 631]);
    }

    #[test]
    fn parses_format_b_open_lines() {
        let output = "Open 127.0.0.1:22\nOpen 127.0.0.1:80\nOpen 127.0.0.1:631";
        assert_eq!(parse_output(output), vec![22, 80, 631]);
    }

    #[test]
    fn parses_format_c_old_greppable() {
        let output = "Host: 192.168.1.1 ()\tPorts: 22/open/tcp/////, 80/open/tcp/////";
        assert_eq!(parse_output(output), vec![22, 80]);
    }

    #[test]
    fn deduplicates_across_formats() {
        // Both format A and B present (rustscan emits both simultaneously)
        let output = "127.0.0.1 -> [22,80]\nOpen 127.0.0.1:22\nOpen 127.0.0.1:80";
        assert_eq!(parse_output(output), vec![22, 80]);
    }

    #[test]
    fn handles_empty_output() {
        assert!(parse_output("").is_empty());
    }

    #[test]
    fn range_detection() {
        assert!(is_range("1-1024"));
        assert!(is_range("1-65535"));
        assert!(!is_range("22,80,443"));
        assert!(!is_range("22"));
    }

    #[test]
    fn args_use_range_flag_for_ranges() {
        let cfg = RustScanConfig {
            host:  "127.0.0.1".into(),
            ports: "1-1024".into(),
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"--range".to_string()));
        assert!(!args.contains(&"--ports".to_string()));
        assert!(args.contains(&"--greppable".to_string()));
        assert!(!args.iter().any(|a| a == "--no-nmap"));
    }

    #[test]
    fn args_use_ports_flag_for_lists() {
        let cfg = RustScanConfig {
            host:  "127.0.0.1".into(),
            ports: "22,80,443".into(),
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"--ports".to_string()));
        assert!(!args.contains(&"--range".to_string()));
    }
}
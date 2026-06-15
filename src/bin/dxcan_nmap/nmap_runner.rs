//! Nmap subprocess runner.
//!
//! Builds the Nmap invocation, spawns it, captures XML on stdout, and
//! forwards stderr for diagnostics. Never interprets results — that's
//! the parser's job.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Everything needed to build an Nmap invocation.
#[derive(Debug, Clone)]
pub struct NmapConfig {
    /// Target host (IP or hostname)
    pub host: String,
    /// Port spec in Nmap format: "22,80,443" or "1-1024" or "-" for all
    pub ports: String,
    /// Enable service/version detection (-sV)
    pub service_detection: bool,
    /// Enable OS detection (-O) — requires root/CAP_NET_RAW
    pub os_detection: bool,
    /// -sV intensity 0–9 (default 5)
    pub version_intensity: u8,
    /// Overall scan timeout; kills the process if exceeded
    pub scan_timeout: Duration,
    /// Nmap timing template T0–T5 (default T4)
    pub timing: u8,
    /// Extra raw args appended verbatim (e.g. ["--script", "banner"])
    pub extra_args: Vec<String>,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            host:               String::new(),
            ports:              String::new(),
            service_detection:  true,
            os_detection:       false, // off by default — requires root
            version_intensity:  5,
            scan_timeout:       Duration::from_secs(300),
            timing:             4,
            extra_args:         vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

pub struct NmapRaw {
    /// Raw Nmap XML string
    pub xml:    String,
    /// Nmap's stderr (warnings, errors, progress lines)
    pub stderr: String,
    /// Nmap exit code
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Check that `nmap` is on PATH and print its version string.
pub async fn check_nmap() -> Result<String, String> {
    let out = Command::new("nmap")
        .arg("--version")
        .output()
        .await
        .map_err(|e| format!("nmap not found or not executable: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("unknown")
        .to_string())
}

/// Build the argument list for this config. Exported for testing/logging.
pub fn build_args(cfg: &NmapConfig) -> Vec<String> {
    let mut args: Vec<String> = vec![
        // XML output to stdout
        "-oX".into(), "-".into(),
        // Port range
        "-p".into(), cfg.ports.clone(),
        // Timing
        format!("-T{}", cfg.timing),
    ];

    if cfg.service_detection {
        args.push("-sV".into());
        args.push("--version-intensity".into());
        args.push(cfg.version_intensity.to_string());
    }

    if cfg.os_detection {
        args.push("-O".into());
    }

    // Always try to resolve hostnames in output
    args.push("-n".into()); // skip reverse DNS to keep output clean

    for extra in &cfg.extra_args {
        args.push(extra.clone());
    }

    args.push(cfg.host.clone());
    args
}

/// Run Nmap and return raw XML + stderr.
pub async fn run(cfg: &NmapConfig) -> Result<NmapRaw, String> {
    let args = build_args(cfg);

    // Spawn
    let mut child = Command::new("nmap")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn nmap: {e}. Is nmap installed?"))?;

    // Collect stdout and stderr concurrently within the timeout
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let result = timeout(cfg.scan_timeout, async {
        let mut xml    = String::new();
        let mut stderr = String::new();

        if let Some(mut out) = stdout_handle {
            out.read_to_string(&mut xml).await.ok();
        }
        if let Some(mut err) = stderr_handle {
            err.read_to_string(&mut stderr).await.ok();
        }

        (xml, stderr)
    })
    .await
    .map_err(|_| format!("Nmap scan timed out after {:?}", cfg.scan_timeout))?;

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Failed to wait for nmap: {e}"))?;

    let exit_code = status.code().unwrap_or(-1);

    // Nmap exits non-zero on some non-fatal conditions (e.g. no hosts up)
    // We do not treat non-zero exit as a hard error — let the caller decide.

    Ok(NmapRaw {
        xml:       result.0,
        stderr:    result.1,
        exit_code,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_service_detection() {
        let cfg = NmapConfig {
            host:   "127.0.0.1".into(),
            ports:  "22,80".into(),
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"-oX".to_string()));
        assert!(args.contains(&"-sV".to_string()));
        assert!(args.contains(&"--version-intensity".to_string()));
        assert!(args.contains(&"5".to_string()));
        assert!(args.last().unwrap() == "127.0.0.1");
    }

    #[test]
    fn args_os_detection_off_by_default() {
        let cfg = NmapConfig {
            host:  "127.0.0.1".into(),
            ports: "1-100".into(),
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(!args.contains(&"-O".to_string()));
    }

    #[test]
    fn args_os_detection_on() {
        let cfg = NmapConfig {
            host:          "127.0.0.1".into(),
            ports:         "1-100".into(),
            os_detection:  true,
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"-O".to_string()));
    }

    #[test]
    fn args_extra_passthrough() {
        let cfg = NmapConfig {
            host:       "10.0.0.1".into(),
            ports:      "443".into(),
            extra_args: vec!["--script".into(), "banner".into()],
            ..Default::default()
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"--script".to_string()));
        assert!(args.contains(&"banner".to_string()));
    }
}
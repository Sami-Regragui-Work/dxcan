pub mod db;
pub mod fingerprint;
pub mod packet;
pub mod probes;
pub mod r#match;
pub mod probe;
pub mod seq_analysis;

use std::net::IpAddr;

pub use probe::{has_raw_privileges, OsDetectResult, OsMatchDetails};

pub fn pick_closed_port(open_ports: &[u16], scanned_closed: &[u16]) -> u16 {
    let mut closed: Vec<u16> = scanned_closed
        .iter()
        .copied()
        .filter(|p| !open_ports.contains(p))
        .collect();
    closed.sort_unstable();
    if let Some(&p) = closed.iter().find(|&&p| p <= 1024) {
        return p;
    }
    if let Some(&p) = closed.first() {
        return p;
    }
    for candidate in [65534u16, 65533, 65532, 65531, 65530] {
        if !open_ports.contains(&candidate) {
            return candidate;
        }
    }
    65534
}

pub fn detect_os(
    target: IpAddr,
    open_ports: &[u16],
    closed_ports: &[u16],
    rtt_ms: f64,
    timeout_ms: u64,
) -> Result<OsDetectResult, String> {
    let closed = pick_closed_port(open_ports, closed_ports);
    probe::detect(target, open_ports, closed_ports, closed, rtt_ms, timeout_ms)
}

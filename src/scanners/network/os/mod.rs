pub mod db;
pub mod fingerprint;
pub mod packet;
pub mod probes;
pub mod r#match;
pub mod probe;
pub mod seq_analysis;

use std::net::IpAddr;

pub use probe::OsDetectResult;

pub fn pick_closed_port(open_ports: &[u16]) -> u16 {
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
    timeout_ms: u64,
) -> Result<OsDetectResult, String> {
    let closed = pick_closed_port(open_ports);
    probe::detect(target, open_ports, closed, timeout_ms)
}

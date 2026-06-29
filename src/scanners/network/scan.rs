use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

use super::os::has_raw_privileges;
use super::port::{scan_port_full, scan_port_open_only, PortProbeOutcome, PortResult};
use super::rtt::RttTracker;
use super::syn_scan::{self, SynScanGoal, SynScanOutput};
use crate::cli::{ScanMethod, ScanMode};

pub struct ScanPlan {
    pub mode: ScanMode,
    pub method: ScanMethod,
    pub verify: bool,
    pub reliable_opens: bool,
}

pub struct ScanOutcome {
    pub results: Vec<PortResult>,
    pub closed_samples: Vec<u16>,
    pub method_label: &'static str,
    pub max_rtt_ms: f64,
}

enum ResolvedEngine {
    Syn,
    Connect,
}

fn resolve_engine(
    method: ScanMethod,
    ip: IpAddr,
    mode: ScanMode,
    reliable_opens: bool,
) -> ResolvedEngine {
    if reliable_opens {
        return ResolvedEngine::Connect;
    }
    match method {
        ScanMethod::Syn => {
            if matches!(ip, IpAddr::V4(_)) && has_raw_privileges() {
                ResolvedEngine::Syn
            } else {
                ResolvedEngine::Connect
            }
        }
        ScanMethod::Connect => ResolvedEngine::Connect,
        ScanMethod::Auto => {
            if mode == ScanMode::Full {
                ResolvedEngine::Connect
            } else if matches!(ip, IpAddr::V4(_)) && has_raw_privileges() {
                ResolvedEngine::Syn
            } else {
                ResolvedEngine::Connect
            }
        }
    }
}

pub fn scan_mode(all: bool) -> ScanMode {
    if all {
        ScanMode::Full
    } else {
        ScanMode::OpenOnly
    }
}

pub async fn run_port_scan(
    ip: IpAddr,
    ports: &[u16],
    timeout_secs: f64,
    workers: usize,
    plan: &ScanPlan,
) -> Result<ScanOutcome, String> {
    let engine = resolve_engine(plan.method, ip, plan.mode, plan.reliable_opens);
    if plan.method == ScanMethod::Syn && !matches!(engine, ResolvedEngine::Syn) {
        eprintln!("[warn] SYN scan requires IPv4 and raw socket privileges; using connect");
    }
    let total = ports.len().max(1);
    let workers = workers.min(total).max(1);
    let base_dur = Duration::from_secs_f64(timeout_secs);
    let rtt = Arc::new(Mutex::new(RttTracker::new(timeout_secs * 1000.0)));
    let sem = Arc::new(Semaphore::new(workers));

    let syn_goal = if plan.mode == ScanMode::Full {
        SynScanGoal::Full
    } else {
        SynScanGoal::OpenOnly
    };

    let (mut results, mut closed_samples, method_label) = match engine {
        ResolvedEngine::Syn => {
            let IpAddr::V4(v4) = ip else {
                return Err("SYN scan requires an IPv4 target".into());
            };
            let SynScanOutput {
                results,
                closed_samples,
            } = syn_scan::scan(v4, ports, timeout_secs, 0.0, syn_goal)?;
            let label = if plan.mode == ScanMode::Full {
                "syn (full)"
            } else {
                "syn (open-only)"
            };
            (results, closed_samples, label)
        }
        ResolvedEngine::Connect if plan.mode == ScanMode::Full => {
            let mut futs = FuturesUnordered::new();
            for &port in ports {
                futs.push(scan_port_full(ip, port, base_dur, sem.clone(), rtt.clone()));
            }
            let mut collected = Vec::with_capacity(ports.len());
            while let Some(r) = futs.next().await {
                collected.push(r);
            }
            collected.sort_unstable_by_key(|r| r.port);
            let closed: Vec<u16> = collected
                .iter()
                .filter(|r| r.state == "closed")
                .map(|r| r.port)
                .collect();
            (collected, closed, "connect (full)")
        }
        ResolvedEngine::Connect => {
            let open_cap = base_dur;
            let closed_samples = Arc::new(Mutex::new(Vec::<u16>::new()));
            let mut futs = FuturesUnordered::new();
            for &port in ports {
                let closed_samples = closed_samples.clone();
                futs.push(scan_port_open_only(
                    ip,
                    port,
                    base_dur,
                    open_cap,
                    sem.clone(),
                    rtt.clone(),
                    closed_samples,
                ));
            }
            let mut collected = Vec::new();
            while let Some(outcome) = futs.next().await {
                if let PortProbeOutcome::Open(r) = outcome {
                    collected.push(r);
                }
            }
            collected.sort_unstable_by_key(|r| r.port);
            let closed = closed_samples.lock().unwrap().clone();
            (collected, closed, "connect (open-only)")
        }
    };

    if plan.verify && !results.is_empty() {
        results = verify_opens(ip, results, base_dur, sem, rtt).await;
    }

    closed_samples.sort_unstable();
    closed_samples.dedup();

    let max_rtt_ms = results
        .iter()
        .map(|r| r.latency_ms)
        .filter(|l| *l > 0.0)
        .fold(100.0_f64, f64::max);

    Ok(ScanOutcome {
        results,
        closed_samples,
        method_label,
        max_rtt_ms,
    })
}

async fn verify_opens(
    ip: IpAddr,
    candidates: Vec<PortResult>,
    base_dur: Duration,
    sem: Arc<Semaphore>,
    rtt: Arc<Mutex<RttTracker>>,
) -> Vec<PortResult> {
    let mut futs = FuturesUnordered::new();
    for r in candidates {
        let port = r.port;
        let sem = sem.clone();
        let rtt = rtt.clone();
        futs.push(async move {
            let confirmed = scan_port_full(ip, port, base_dur, sem, rtt).await;
            if confirmed.state == "open" {
                Some(confirmed)
            } else {
                None
            }
        });
    }
    let mut verified = Vec::new();
    while let Some(opt) = futs.next().await {
        if let Some(r) = opt {
            verified.push(r);
        }
    }
    verified.sort_unstable_by_key(|r| r.port);
    verified
}

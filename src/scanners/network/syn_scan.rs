use std::collections::{HashMap, HashSet};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::scanners::network::os::packet::build_tcp_packet;
use crate::scanners::network::os::probes::{TH_ACK, TH_RST, TH_SYN};
use crate::scanners::network::port::PortResult;

const SEND_BATCH: usize = 512;
const IDLE_EXIT_MS: u64 = 80;
const BATCH_MIN_LISTEN_MS: u64 = 100;
const FINAL_DRAIN_MS: u64 = 1200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynScanGoal {
    OpenOnly,
    Full,
}

pub struct SynScanOutput {
    pub results: Vec<PortResult>,
    pub closed_samples: Vec<u16>,
}

pub fn scan(
    target: Ipv4Addr,
    ports: &[u16],
    _timeout_secs: f64,
    rtt_hint_ms: f64,
    goal: SynScanGoal,
) -> Result<SynScanOutput, String> {
    if ports.is_empty() {
        return Ok(SynScanOutput {
            results: Vec::new(),
            closed_samples: Vec::new(),
        });
    }
    let src_ip = local_ipv4_for(target)?;
    let send_fd = raw_socket(libc::IPPROTO_RAW)?;
    let recv_fd = raw_socket(libc::IPPROTO_TCP)?;
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            send_fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            mem::size_of_val(&one) as libc::socklen_t,
        );
    }

    let mut port_by_src: HashMap<u16, u16> = HashMap::with_capacity(ports.len());
    let mut pending: HashSet<u16> = HashSet::with_capacity(ports.len());
    let mut opens: HashMap<u16, PortResult> = HashMap::new();
    let mut closed_samples: Vec<u16> = Vec::new();
    let mut full_results: HashMap<u16, PortResult> = HashMap::new();
    let mut send_times: HashMap<u16, Instant> = HashMap::with_capacity(ports.len());
    let seq = 0x5a5a_0000u32;
    let mut learned_rtt_ms = if rtt_hint_ms > 0.0 { rtt_hint_ms } else { 150.0 };
    let batch_listen_ms = batch_listen_ms(rtt_hint_ms, goal);

    for (batch_idx, chunk) in ports.chunks(SEND_BATCH).enumerate() {
        for (i, &dst_port) in chunk.iter().enumerate() {
            let global_i = batch_idx * SEND_BATCH + i;
            let src_port = src_port_for_index(global_i);
            port_by_src.insert(src_port, dst_port);
            pending.insert(dst_port);
            let pkt = build_tcp_packet(
                src_ip,
                target,
                src_port,
                dst_port,
                TH_SYN,
                1024,
                seq.wrapping_add(global_i as u32),
                0,
                0,
                false,
                &[],
            );
            let sent_at = Instant::now();
            send_packet(send_fd, target, &pkt)?;
            send_times.insert(dst_port, sent_at);
        }

        let mut last_activity = Instant::now();
        let batch_deadline = Instant::now() + Duration::from_millis(batch_listen_ms);
        let batch_min = Instant::now() + Duration::from_millis(BATCH_MIN_LISTEN_MS);
        learned_rtt_ms = recv_until(
            recv_fd,
            target,
            src_ip,
            &port_by_src,
            &send_times,
            &mut pending,
            &mut opens,
            &mut closed_samples,
            &mut full_results,
            goal,
            &mut last_activity,
            batch_min,
            batch_deadline,
            learned_rtt_ms,
        );
    }

    if !pending.is_empty() {
        let mut last_activity = Instant::now();
        let final_deadline = Instant::now() + Duration::from_millis(FINAL_DRAIN_MS);
        let final_min = Instant::now() + Duration::from_millis(BATCH_MIN_LISTEN_MS);
        recv_until(
            recv_fd,
            target,
            src_ip,
            &port_by_src,
            &send_times,
            &mut pending,
            &mut opens,
            &mut closed_samples,
            &mut full_results,
            goal,
            &mut last_activity,
            final_min,
            final_deadline,
            learned_rtt_ms,
        );
    }

    if goal == SynScanGoal::Full {
        let default_latency = if rtt_hint_ms > 0.0 {
            rtt_hint_ms
        } else {
            full_results
                .values()
                .chain(opens.values())
                .filter(|r| r.latency_ms > 0.0)
                .map(|r| r.latency_ms)
                .fold(50.0_f64, f64::max)
        };
        for &port in ports {
            if full_results.contains_key(&port) {
                continue;
            }
            full_results.insert(
                port,
                PortResult {
                    port,
                    protocol: "tcp".into(),
                    state: "filtered".into(),
                    latency_ms: default_latency,
                    error: None,
                },
            );
        }
    }

    unsafe {
        libc::close(send_fd);
        libc::close(recv_fd);
    }

    closed_samples.sort_unstable();
    closed_samples.dedup();

    let results = if goal == SynScanGoal::Full {
        let mut out: Vec<PortResult> = full_results.into_values().collect();
        out.sort_unstable_by_key(|r| r.port);
        out
    } else {
        let mut out: Vec<PortResult> = opens.into_values().collect();
        out.sort_unstable_by_key(|r| r.port);
        out
    };

    Ok(SynScanOutput {
        results,
        closed_samples,
    })
}

fn src_port_for_index(i: usize) -> u16 {
    if i < 64512 {
        (1024 + i) as u16
    } else {
        (i - 64512 + 1) as u16
    }
}

fn batch_listen_ms(rtt_hint_ms: f64, goal: SynScanGoal) -> u64 {
    if rtt_hint_ms > 0.0 {
        let base = if goal == SynScanGoal::OpenOnly {
            rtt_hint_ms * 3.0 + 250.0
        } else {
            rtt_hint_ms * 4.0 + 350.0
        };
        return base.clamp(350.0, 1500.0) as u64;
    }
    if goal == SynScanGoal::OpenOnly {
        450
    } else {
        600
    }
}

#[allow(clippy::too_many_arguments)]
fn recv_until(
    recv_fd: i32,
    target: Ipv4Addr,
    src_ip: Ipv4Addr,
    port_by_src: &HashMap<u16, u16>,
    send_times: &HashMap<u16, Instant>,
    pending: &mut HashSet<u16>,
    opens: &mut HashMap<u16, PortResult>,
    closed_samples: &mut Vec<u16>,
    full_results: &mut HashMap<u16, PortResult>,
    goal: SynScanGoal,
    last_activity: &mut Instant,
    min_deadline: Instant,
    max_deadline: Instant,
    learned_rtt_ms: f64,
) -> f64 {
    let mut rtt = learned_rtt_ms;
    let mut buf = [0u8; 65535];
    loop {
        if pending.is_empty() {
            break;
        }
        let now = Instant::now();
        if now >= max_deadline {
            break;
        }
        if now >= min_deadline && last_activity.elapsed() >= Duration::from_millis(IDLE_EXIT_MS) {
            break;
        }
        let remaining = max_deadline.saturating_duration_since(now);
        let slice = remaining.min(Duration::from_millis(50));
        let mut read_set: libc::fd_set = unsafe { mem::zeroed() };
        unsafe {
            libc::FD_ZERO(&mut read_set);
            libc::FD_SET(recv_fd, &mut read_set);
        }
        let mut tv = libc::timeval {
            tv_sec: slice.as_secs() as libc::time_t,
            tv_usec: slice.subsec_micros() as libc::suseconds_t,
        };
        let ready = unsafe {
            libc::select(
                recv_fd + 1,
                &mut read_set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            )
        };
        if ready <= 0 {
            continue;
        }
        let n = unsafe {
            libc::recv(
                recv_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 40 {
            continue;
        }
        *last_activity = Instant::now();
        let Some((remote_port, flags, latency_ms)) =
            parse_syn_reply(&buf[..n as usize], target, src_ip, port_by_src, send_times)
        else {
            continue;
        };
        if latency_ms > 0.0 && latency_ms < rtt * 4.0 {
            rtt = rtt * 0.7 + latency_ms * 0.3;
        }
        if !pending.contains(&remote_port) {
            continue;
        }
        if flags & (TH_SYN | TH_ACK) == (TH_SYN | TH_ACK) {
            pending.remove(&remote_port);
            let entry = PortResult {
                port: remote_port,
                protocol: "tcp".into(),
                state: "open".into(),
                latency_ms,
                error: None,
            };
            opens.insert(remote_port, entry.clone());
            if goal == SynScanGoal::Full {
                full_results.insert(remote_port, entry);
            }
        } else if flags & TH_RST != 0 {
            pending.remove(&remote_port);
            closed_samples.push(remote_port);
            if goal == SynScanGoal::Full {
                full_results.insert(
                    remote_port,
                    PortResult {
                        port: remote_port,
                        protocol: "tcp".into(),
                        state: "closed".into(),
                        latency_ms,
                        error: None,
                    },
                );
            }
        }
    }
    rtt
}

fn parse_syn_reply(
    buf: &[u8],
    expected_src: Ipv4Addr,
    our_ip: Ipv4Addr,
    port_by_src: &HashMap<u16, u16>,
    send_times: &HashMap<u16, Instant>,
) -> Option<(u16, u8, f64)> {
    if buf.len() < 40 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 20 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    if src != expected_src || dst != our_ip {
        return None;
    }
    let tcp = &buf[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let remote_port = port_by_src.get(&dst_port).copied()?;
    if src_port != remote_port {
        return None;
    }
    let latency_ms = send_times
        .get(&remote_port)
        .map(|t| t.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    Some((remote_port, tcp[13], latency_ms))
}

fn send_packet(fd: i32, target: Ipv4Addr, packet: &[u8]) -> Result<(), String> {
    let dst = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(target).to_be(),
        },
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            mem::size_of_val(&dst) as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn raw_socket(proto: i32) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(format!(
            "raw socket failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

fn local_ipv4_for(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(SocketAddr::from((target, 80)))
        .map_err(|e| e.to_string())?;
    match sock.local_addr().map_err(|e| e.to_string())?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => Err("Could not determine local IPv4 address".into()),
    }
}

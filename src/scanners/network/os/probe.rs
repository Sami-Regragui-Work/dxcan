use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::db;
use super::fingerprint::{ack_class, format_flags, ttl_bucket, Fingerprint};
use super::packet::{
    build_icmp_echo, build_tcp_packet, build_udp_packet, parse_icmp_echo_reply,
    parse_icmp_unreach, parse_ip_tcp, tcp_options_string, tcp_timestamp, ParsedIpTcp,
};
use super::probes::{
    pick_closed_udp_port, ECN_URG_PTR, NUM_SEQ, PRB_OPTS, PRB_WINDOWS, TCP_PORT_BASE,
    TH_ACK, TH_CWR, TH_ECE, TH_FIN, TH_PUSH, TH_SYN, TH_URG,
};
use super::r#match;
use super::seq_analysis::{fill_seq_fields, fill_seq_ipid_fields, SeqSamples};

#[derive(Debug, Clone, Default)]
pub struct OsMatchDetails {
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub os_gen: Option<String>,
    pub device_type: Option<String>,
    pub running: Option<String>,
    pub cpes: Vec<String>,
    pub product_hints: Vec<String>,
}

impl OsMatchDetails {
    pub fn nmap_running_line(&self) -> Option<String> {
        if let Some(r) = &self.running {
            if !r.is_empty() {
                return Some(r.clone());
            }
        }
        match (&self.os_family, &self.os_gen) {
            (Some(f), Some(g)) if !f.is_empty() && !g.is_empty() => {
                Some(format!("{f} {g}"))
            }
            (Some(f), _) if !f.is_empty() => Some(f.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OsDetectResult {
    pub fingerprint: Fingerprint,
    pub detection_ms: f64,
    pub guess: Option<String>,
    pub accuracy: Option<u8>,
    pub details: OsMatchDetails,
}

pub fn has_raw_privileges() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            false
        }
    }
}

pub fn detect(
    target: IpAddr,
    open_ports: &[u16],
    _closed_candidates: &[u16],
    closed_tcp: u16,
    rtt_ms: f64,
    timeout_ms: u64,
) -> Result<OsDetectResult, String> {
    let IpAddr::V4(target_v4) = target else {
        return Err("OS detection requires IPv4 target".into());
    };
    if !has_raw_privileges() {
        return Err("OS detection requires root or CAP_NET_RAW (same as nmap -O)".into());
    }
    if open_ports.is_empty() {
        return Err("OS detection requires at least one open port".into());
    }

    let start = Instant::now();
    let src_ip = local_ipv4_for(target_v4)?;
    let open_port = open_ports[0];
    let closed_udp = pick_closed_udp_port(open_ports);
    let per_probe_cap = (timeout_ms as f64 * 0.25).clamp(150.0, 500.0);
    let per_probe_ms = ((rtt_ms * 3.0).max(150.0).min(per_probe_cap)) as u64;
    let timeout = Duration::from_millis(per_probe_ms);
    let seq_delay_ms = ((rtt_ms * 0.4) as u64).clamp(10, 50);
    let mut engine = ProbeEngine::new(src_ip, target_v4, timeout)?;
    let seq_base = rand_seq();
    engine.seq_base = seq_base;
    let mut fp = Fingerprint::default();
    let mut samples = SeqSamples::new();
    let mut ops: [Option<TcpReply>; NUM_SEQ] = [None, None, None, None, None, None];
    let mut t: [Option<TcpReply>; 7] = [None, None, None, None, None, None, None];
    let mut tcp_open_ids: [Option<u16>; NUM_SEQ] = [None; NUM_SEQ];
    let mut tcp_closed_ids: [Option<u16>; 3] = [None; 3];
    let mut icmp_ids: [Option<u16>; 2] = [None; 2];
    let mut ie: [Option<IcmpReply>; 2] = [None, None];

    for i in 0..NUM_SEQ {
        let src_port = TCP_PORT_BASE + i as u16;
        let seq = seq_base.wrapping_add(i as u32);
        engine.send_tcp(
            open_port,
            src_port,
            TH_SYN,
            PRB_WINDOWS[i],
            seq,
            0,
            0,
            false,
            PRB_OPTS[i],
        )?;
        if let Some(reply) = engine.recv_tcp(open_port, src_port, seq) {
            if reply.syn_ack {
                let ts = tcp_timestamp(&reply.raw_options).unwrap_or(0);
                samples.record(i, reply.seq, reply.ip_id, ts);
                tcp_open_ids[i] = Some(reply.ip_id);
                if i == 0 {
                    t[0] = Some(reply);
                }
            }
        }
        if i + 1 < NUM_SEQ {
            std::thread::sleep(Duration::from_millis(seq_delay_ms));
        }
    }

    fill_seq_fields(&mut fp, &samples, seq_delay_ms);

    for i in 0..2 {
        let df = i == 0;
        let tos = if i == 0 { 0 } else { 4 };
        let code = if i == 0 { 9 } else { 0 };
        let ident = 295u16 + i as u16;
        let seq = 295u16 + i as u16;
        let payload = if i == 0 { 120 } else { 150 };
        engine.send_icmp(df, tos, code, ident, seq, payload)?;
        if let Some(reply) = engine.recv_icmp_echo() {
            icmp_ids[i] = Some(reply.ip_id);
            ie[i] = Some(reply);
        }
    }
    fill_ie(&mut fp, &ie);

    let udp_payload = vec![b'C'; 300];
    engine.send_udp(closed_udp, TCP_PORT_BASE + 20, 0x1042, &udp_payload)?;
    if let Some(reply) = engine.recv_icmp_unreach() {
        fill_u1(&mut fp, &reply);
    } else {
        mark_test_absent(&mut fp, "U1");
    }

    for i in 0..NUM_SEQ {
        let src_port = TCP_PORT_BASE + 6 + i as u16;
        engine.send_tcp(
            open_port,
            src_port,
            TH_SYN,
            PRB_WINDOWS[i],
            seq_base,
            0,
            0,
            false,
            PRB_OPTS[i],
        )?;
        if let Some(reply) = engine.recv_tcp(open_port, src_port, seq_base) {
            if reply.syn_ack {
                ops[i] = Some(reply);
            }
        }
    }
    fill_ops_win(&mut fp, &ops);

    let ecn_port = TCP_PORT_BASE + 12;
    engine.send_tcp(
        open_port,
        ecn_port,
        TH_CWR | TH_ECE | TH_SYN,
        PRB_WINDOWS[6],
        seq_base,
        0,
        ECN_URG_PTR,
        false,
        PRB_OPTS[6],
    )?;
    if let Some(reply) = engine.recv_tcp(open_port, ecn_port, seq_base) {
        fill_ecn(&mut fp, &reply);
    } else {
        mark_test_absent(&mut fp, "ECN");
    }

    let t_specs: [(usize, u8, usize, u16, bool, usize); 6] = [
        (1, 0, 7, 0, true, 7),
        (2, TH_SYN | TH_FIN | TH_URG | TH_PUSH, 8, 0, false, 8),
        (3, TH_ACK, 9, 0, true, 9),
        (4, TH_SYN, 10, 0, false, 10),
        (5, TH_ACK, 11, 0, true, 11),
        (6, TH_FIN | TH_PUSH | TH_URG, 12, 0, false, 12),
    ];
    for (idx, flags, win_i, urg, df, prb_i) in t_specs {
        let port = if idx >= 4 { closed_tcp } else { open_port };
        let src_port = TCP_PORT_BASE + 13 + (idx - 1) as u16;
        engine.send_tcp(
            port,
            src_port,
            flags,
            PRB_WINDOWS[win_i],
            seq_base,
            0,
            urg,
            df,
            PRB_OPTS[prb_i],
        )?;
        if let Some(reply) = engine.recv_tcp(port, src_port, seq_base) {
            if idx >= 4 {
                tcp_closed_ids[idx - 4] = Some(reply.ip_id);
            }
            t[idx] = Some(reply);
        }
    }
    fill_seq_ipid_fields(&mut fp, &tcp_open_ids, &tcp_closed_ids, &icmp_ids);

    for (i, reply) in t.iter().enumerate() {
        let name = format!("T{}", i + 1);
        if let Some(r) = reply {
            fill_tcp_test(&mut fp, &name, r, i == 0);
        } else {
            mark_test_absent(&mut fp, &name);
        }
    }

    let detection_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut result = OsDetectResult {
        fingerprint: fp,
        detection_ms,
        guess: None,
        accuracy: None,
        details: OsMatchDetails::default(),
    };

    match db::database() {
        Ok(db) => {
            let pick = r#match::best_match_fingerprint(
                &result.fingerprint,
                &db.match_points,
                &db.entries,
                85,
            )
            .or_else(|| {
                r#match::best_match_fingerprint(
                    &result.fingerprint,
                    &db.match_points,
                    &db.entries,
                    50,
                )
            });
            if let Some(m) = pick {
                result.guess = Some(m.name);
                result.accuracy = Some(m.accuracy);
                result.details = OsMatchDetails {
                    vendor: m.vendor,
                    os_family: m.os_family,
                    os_gen: m.os_gen,
                    device_type: m.device_type,
                    running: m.running,
                    cpes: m.cpes,
                    product_hints: Vec::new(),
                };
            }
        }
        Err(e) => {
            eprintln!("[warn] {e}");
        }
    }

    Ok(result)
}

#[derive(Clone)]
struct TcpReply {
    ip_id: u16,
    ttl: u8,
    dont_fragment: bool,
    window: u16,
    flags: String,
    options: String,
    ack_class: String,
    seq: u32,
    syn_ack: bool,
    raw_options: Vec<u8>,
    tcp_flags: u8,
}

#[derive(Clone)]
struct IcmpReply {
    ip_id: u16,
    ttl: u8,
    dont_fragment: bool,
    code: u8,
}

struct ProbeEngine {
    send_fd: i32,
    recv_tcp_fd: i32,
    recv_icmp_fd: i32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    seq_base: u32,
    timeout: Duration,
}

impl ProbeEngine {
    fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, timeout: Duration) -> Result<Self, String> {
        let send_fd = raw_socket(libc::IPPROTO_RAW)?;
        let recv_tcp_fd = raw_socket(libc::IPPROTO_TCP)?;
        let recv_icmp_fd = raw_socket(libc::IPPROTO_ICMP)?;
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
        Ok(Self {
            send_fd,
            recv_tcp_fd,
            recv_icmp_fd,
            src_ip,
            dst_ip,
            seq_base: 0,
            timeout,
        })
    }

    fn send_tcp(
        &self,
        dst_port: u16,
        src_port: u16,
        flags: u8,
        window: u16,
        seq: u32,
        ack: u32,
        urg_ptr: u16,
        df: bool,
        options: &[u8],
    ) -> Result<(), String> {
        let packet = build_tcp_packet(
            self.src_ip,
            self.dst_ip,
            src_port,
            dst_port,
            flags,
            window,
            seq,
            ack,
            urg_ptr,
            df,
            options,
        );
        self.send_ip(packet)
    }

    fn send_udp(
        &self,
        dst_port: u16,
        src_port: u16,
        ip_id: u16,
        payload: &[u8],
    ) -> Result<(), String> {
        let packet = build_udp_packet(self.src_ip, self.dst_ip, src_port, dst_port, ip_id, payload);
        self.send_ip(packet)
    }

    fn send_icmp(
        &self,
        df: bool,
        tos: u8,
        code: u8,
        ident: u16,
        seq: u16,
        payload_len: usize,
    ) -> Result<(), String> {
        let ip_id = 0x295 + seq;
        let packet = build_icmp_echo(
            self.src_ip,
            self.dst_ip,
            ip_id,
            df,
            tos,
            code,
            ident,
            seq,
            payload_len,
        );
        self.send_ip(packet)
    }

    fn send_ip(&self, packet: Vec<u8>) -> Result<(), String> {
        let dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(self.dst_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        let ret = unsafe {
            libc::sendto(
                self.send_fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of_val(&dst) as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(format!(
                "sendto failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn recv_tcp(&self, remote_port: u16, our_port: u16, our_seq: u32) -> Option<TcpReply> {
        let deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; 65535];
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut read_set: libc::fd_set = unsafe { mem::zeroed() };
            unsafe {
                libc::FD_ZERO(&mut read_set);
                libc::FD_SET(self.recv_tcp_fd, &mut read_set);
            }
            let mut tv = libc::timeval {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_usec: remaining.subsec_micros() as libc::suseconds_t,
            };
            let ready = unsafe {
                libc::select(
                    self.recv_tcp_fd + 1,
                    &mut read_set,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if ready <= 0 {
                break;
            }
            let n = unsafe {
                libc::recv(
                    self.recv_tcp_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 20 {
                continue;
            }
            if let Some(parsed) = parse_ip_tcp(
                &buf[..n as usize],
                self.dst_ip,
                our_port,
                remote_port,
            ) {
                return Some(tcp_reply_from(parsed, our_seq));
            }
        }
        None
    }

    fn recv_icmp_echo(&self) -> Option<IcmpReply> {
        self.recv_icmp(true)
    }

    fn recv_icmp_unreach(&self) -> Option<IcmpReply> {
        self.recv_icmp(false)
    }

    fn recv_icmp(&self, echo: bool) -> Option<IcmpReply> {
        let deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; 65535];
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut read_set: libc::fd_set = unsafe { mem::zeroed() };
            unsafe {
                libc::FD_ZERO(&mut read_set);
                libc::FD_SET(self.recv_icmp_fd, &mut read_set);
            }
            let mut tv = libc::timeval {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_usec: remaining.subsec_micros() as libc::suseconds_t,
            };
            let ready = unsafe {
                libc::select(
                    self.recv_icmp_fd + 1,
                    &mut read_set,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if ready <= 0 {
                break;
            }
            let n = unsafe {
                libc::recv(
                    self.recv_icmp_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 28 {
                continue;
            }
            let parsed = if echo {
                parse_icmp_echo_reply(&buf[..n as usize], self.dst_ip)
            } else {
                parse_icmp_unreach(&buf[..n as usize], self.dst_ip)
            };
            if let Some(p) = parsed {
                return Some(IcmpReply {
                    ip_id: p.ip_id,
                    ttl: p.ttl,
                    dont_fragment: p.dont_fragment,
                    code: p.icmp_code,
                });
            }
        }
        None
    }
}

impl Drop for ProbeEngine {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.send_fd);
            libc::close(self.recv_tcp_fd);
            libc::close(self.recv_icmp_fd);
        }
    }
}

fn tcp_reply_from(parsed: ParsedIpTcp, our_seq: u32) -> TcpReply {
    let syn_ack = parsed.flags & (TH_SYN | TH_ACK) == (TH_SYN | TH_ACK);
    let options = tcp_options_string(&parsed.options);
    TcpReply {
        ip_id: parsed.ip_id,
        ttl: parsed.ttl,
        dont_fragment: parsed.dont_fragment,
        window: parsed.window,
        flags: format_flags(parsed.flags),
        options: options.clone(),
        ack_class: ack_class(parsed.seq, parsed.ack, our_seq),
        seq: parsed.seq,
        syn_ack,
        raw_options: parsed.options,
        tcp_flags: parsed.flags,
    }
}

fn mark_test_absent(fp: &mut Fingerprint, test: &str) {
    fp.set(test, "R", "N");
}

fn fill_ops_win(fp: &mut Fingerprint, ops: &[Option<TcpReply>; NUM_SEQ]) {
    for (i, reply) in ops.iter().enumerate() {
        let key = format!("O{}", i + 1);
        if let Some(r) = reply {
            fp.set("OPS", &key, &r.options);
            fp.set("WIN", &format!("W{}", i + 1), format!("{:X}", r.window));
        } else {
            fp.set("OPS", &key, "");
            fp.set("WIN", &format!("W{}", i + 1), "0");
        }
    }
}

fn fill_ecn(fp: &mut Fingerprint, r: &TcpReply) {
    fp.set("ECN", "R", "Y");
    fp.set("ECN", "DF", yn(r.dont_fragment));
    fp.set("ECN", "T", format!("{:X}", r.ttl));
    fp.set("ECN", "TG", ttl_bucket(r.ttl));
    fp.set("ECN", "W", format!("{:X}", r.window));
    fp.set("ECN", "O", &r.options);
    fp.set("ECN", "CC", ecn_class(r.tcp_flags));
    fp.set("ECN", "Q", "");
}

fn ecn_class(flags: u8) -> String {
    let ece = flags & TH_ECE != 0;
    let cwr = flags & TH_CWR != 0;
    if ece && !cwr {
        "Y".into()
    } else if !ece && !cwr {
        "N".into()
    } else if ece && cwr {
        "S".into()
    } else {
        "N".into()
    }
}

fn fill_u1(fp: &mut Fingerprint, r: &IcmpReply) {
    fp.set("U1", "R", "Y");
    fp.set("U1", "DF", yn(r.dont_fragment));
    fp.set("U1", "T", format!("{:X}", r.ttl));
    fp.set("U1", "TG", ttl_bucket(r.ttl));
    fp.set("U1", "IPL", "38");
    fp.set("U1", "UN", "0");
    fp.set("U1", "RIPL", "G");
    fp.set("U1", "RID", "G");
    fp.set("U1", "RIPCK", "G");
    fp.set("U1", "RUCK", "G");
    fp.set("U1", "RUD", "G");
}

fn fill_ie(fp: &mut Fingerprint, replies: &[Option<IcmpReply>; 2]) {
    let r0 = replies[0].as_ref();
    let r1 = replies[1].as_ref();
    if r0.is_none() || r1.is_none() {
        fp.set("IE", "R", "N");
        return;
    }
    let a = r0.unwrap();
    let b = r1.unwrap();
    fp.set("IE", "R", "Y");
    fp.set("IE", "DFI", ie_dfi(a.dont_fragment, b.dont_fragment));
    fp.set("IE", "T", format!("{:X}", a.ttl));
    fp.set("IE", "TG", ttl_bucket(a.ttl));
    fp.set("IE", "CD", if a.code == 0 { "S" } else { "O" });
}

fn ie_dfi(a: bool, b: bool) -> String {
    match (a, b) {
        (false, false) => "N".into(),
        (true, true) => "Y".into(),
        (false, true) | (true, false) => "O".into(),
    }
}

fn fill_tcp_test(fp: &mut Fingerprint, test: &str, r: &TcpReply, t1_style: bool) {
    fp.set(test, "R", "Y");
    fp.set(test, "DF", yn(r.dont_fragment));
    fp.set(test, "T", format!("{:X}", r.ttl));
    fp.set(test, "TG", ttl_bucket(r.ttl));
    if t1_style {
        fp.set(test, "S", "O");
        fp.set(test, "A", &r.ack_class);
        fp.set(test, "F", &r.flags);
        fp.set(test, "RD", "0");
        fp.set(test, "Q", "");
    } else {
        fp.set(test, "W", format!("{:X}", r.window));
        fp.set(test, "S", "O");
        fp.set(test, "A", &r.ack_class);
        fp.set(test, "O", &r.options);
        fp.set(test, "F", &r.flags);
        fp.set(test, "RD", "0");
        fp.set(test, "Q", "");
    }
}

fn yn(v: bool) -> String {
    if v {
        "Y".into()
    } else {
        "N".into()
    }
}

fn local_ipv4_for(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(SocketAddr::new(IpAddr::V4(target), 80))
        .map_err(|e| e.to_string())?;
    match sock.local_addr().map_err(|e| e.to_string())?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        _ => Err("Could not determine local IPv4 address".into()),
    }
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

fn rand_seq() -> u32 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    0x1000_0000u32.wrapping_add(t)
}

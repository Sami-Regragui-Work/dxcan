use std::net::Ipv4Addr;

use super::fingerprint::format_tcp_options;

pub const IP_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;

pub struct ParsedIpTcp {
    pub ip_id: u16,
    pub ttl: u8,
    pub dont_fragment: bool,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: Vec<u8>,
}

pub struct ParsedIcmp {
    pub ip_id: u16,
    pub ttl: u8,
    pub dont_fragment: bool,
    pub icmp_code: u8,
}

pub fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    window: u16,
    seq: u32,
    ack: u32,
    urg_ptr: u16,
    df: bool,
    options: &[u8],
) -> Vec<u8> {
    let tcp_len = TCP_HEADER_LEN + options.len();
    let total_len = IP_HEADER_LEN + tcp_len;
    let mut packet = vec![0u8; total_len];

    packet[0] = 0x45;
    if df {
        packet[6] = 0x40;
    }
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    let tcp_off = IP_HEADER_LEN;
    packet[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp_off + 12] = ((5 + options.len() / 4) as u8) << 4;
    packet[tcp_off + 13] = flags;
    packet[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
    packet[tcp_off + 18..tcp_off + 20].copy_from_slice(&urg_ptr.to_be_bytes());
    if !options.is_empty() {
        packet[tcp_off + TCP_HEADER_LEN..tcp_off + tcp_len].copy_from_slice(options);
    }

    let ip_csum = checksum(&packet[..IP_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let tcp_csum = tcp_checksum(src, dst, &packet[tcp_off..tcp_off + tcp_len]);
    packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    packet
}

pub fn build_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = IP_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let off = IP_HEADER_LEN;
    packet[off..off + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[off + 2..off + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[off + 4..off + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[off + 6..off + 8].copy_from_slice(&0u16.to_be_bytes());
    packet[off + 8..off + 8 + payload.len()].copy_from_slice(payload);
    let ip_csum = checksum(&packet[..IP_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let udp_csum = udp_checksum(src, dst, &packet[off..]);
    packet[off + 6..off + 8].copy_from_slice(&udp_csum.to_be_bytes());
    packet
}

pub fn build_icmp_echo(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ip_id: u16,
    df: bool,
    tos: u8,
    icmp_code: u8,
    ident: u16,
    seq: u16,
    payload_len: usize,
) -> Vec<u8> {
    let icmp_len = 8 + payload_len;
    let total_len = IP_HEADER_LEN + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    if df {
        packet[6] = 0x40;
    }
    packet[1] = tos;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let off = IP_HEADER_LEN;
    packet[off] = 8;
    packet[off + 1] = icmp_code;
    packet[off + 2..off + 4].copy_from_slice(&0u16.to_be_bytes());
    packet[off + 4..off + 6].copy_from_slice(&ident.to_be_bytes());
    packet[off + 6..off + 8].copy_from_slice(&seq.to_be_bytes());
    let ip_csum = checksum(&packet[..IP_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_csum = icmp_checksum(src, dst, &packet[off..]);
    packet[off + 2..off + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    packet
}

pub fn parse_ip_tcp(
    buf: &[u8],
    expected_src: Ipv4Addr,
    expected_dst_port: u16,
    expected_src_port: u16,
) -> Option<ParsedIpTcp> {
    if buf.len() < 40 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 20 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    if src != expected_src {
        return None;
    }
    let ip_id = u16::from_be_bytes([buf[4], buf[5]]);
    let tcp = &buf[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != expected_dst_port || src_port != expected_src_port {
        return None;
    }
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_off {
        return None;
    }
    Some(ParsedIpTcp {
        ip_id,
        ttl: buf[8],
        dont_fragment: (buf[6] & 0x40) != 0,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        options: tcp[20..data_off.min(tcp.len())].to_vec(),
    })
}

pub fn parse_icmp_unreach(
    buf: &[u8],
    expected_src: Ipv4Addr,
) -> Option<ParsedIcmp> {
    if buf.len() < 28 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    if src != expected_src {
        return None;
    }
    let icmp = &buf[ihl..];
    let icmp_type = icmp[0];
    if icmp_type != 3 {
        return None;
    }
    Some(ParsedIcmp {
        ip_id: u16::from_be_bytes([buf[4], buf[5]]),
        ttl: buf[8],
        dont_fragment: (buf[6] & 0x40) != 0,
        icmp_code: icmp[1],
    })
}

pub fn parse_icmp_echo_reply(buf: &[u8], expected_src: Ipv4Addr) -> Option<ParsedIcmp> {
    if buf.len() < 28 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    if src != expected_src {
        return None;
    }
    let icmp = &buf[ihl..];
    if icmp[0] != 0 {
        return None;
    }
    Some(ParsedIcmp {
        ip_id: u16::from_be_bytes([buf[4], buf[5]]),
        ttl: buf[8],
        dont_fragment: (buf[6] & 0x40) != 0,
        icmp_code: icmp[1],
    })
}

pub fn tcp_options_string(options: &[u8]) -> String {
    format_tcp_options(options)
}

pub fn tcp_timestamp(options: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i < options.len() {
        let kind = options[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if len < 2 || i + len > options.len() {
            break;
        }
        if kind == 8 && len >= 10 {
            return Some(u32::from_be_bytes([
                options[i + 2],
                options[i + 3],
                options[i + 4],
                options[i + 5],
            ]));
        }
        i += len;
    }
    None
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    checksum(&pseudo)
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

fn icmp_checksum(src: Ipv4Addr, dst: Ipv4Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + icmp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(1);
    pseudo.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(icmp);
    checksum(&pseudo)
}

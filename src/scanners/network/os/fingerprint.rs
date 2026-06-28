use std::collections::HashMap;

use super::probes::{TH_ACK, TH_CWR, TH_ECE, TH_FIN, TH_PUSH, TH_RST, TH_SYN, TH_URG};

#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    pub tests: HashMap<String, HashMap<String, String>>,
}

impl Fingerprint {
    pub fn set(&mut self, test: &str, field: &str, value: impl Into<String>) {
        self.tests
            .entry(test.to_string())
            .or_default()
            .insert(field.to_string(), value.into());
    }

    pub fn test_block(&self, test: &str) -> Option<&HashMap<String, String>> {
        self.tests.get(test)
    }
}

pub fn format_tcp_options(opts: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => break,
            1 => {
                out.push('N');
                i += 1;
            }
            2 if i + 3 < opts.len() => {
                let mss = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                out.push_str(&format!("M{mss:X}"));
                i += 4;
            }
            3 if i + 2 < opts.len() => {
                out.push_str(&format!("W{}", opts[i + 2]));
                i += 3;
            }
            4 => {
                out.push('S');
                i += 2;
            }
            8 if i + 9 < opts.len() => {
                let tsval = u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                let tsecr = u32::from_be_bytes([opts[i + 6], opts[i + 7], opts[i + 8], opts[i + 9]]);
                out.push('T');
                out.push(if tsval == 0 { '0' } else { '1' });
                out.push(if tsecr == 0 { '0' } else { '1' });
                i += 10;
            }
            _ => {
                if kind >= 2 && i + 1 < opts.len() {
                    let len = opts[i + 1] as usize;
                    if len >= 2 && i + len <= opts.len() {
                        i += len;
                        continue;
                    }
                }
                out.push('?');
                i += 1;
            }
        }
    }
    out
}

pub fn format_flags(flags: u8) -> String {
    let mut s = String::new();
    if flags & TH_FIN != 0 {
        s.push('F');
    }
    if flags & TH_SYN != 0 {
        s.push('S');
    }
    if flags & TH_RST != 0 {
        s.push('R');
    }
    if flags & TH_PUSH != 0 {
        s.push('P');
    }
    if flags & TH_ACK != 0 {
        s.push('A');
    }
    if flags & TH_URG != 0 {
        s.push('U');
    }
    if flags & TH_ECE != 0 {
        s.push('E');
    }
    if flags & TH_CWR != 0 {
        s.push('C');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

pub fn ttl_bucket(ttl: u8) -> String {
    let tg = if ttl <= 32 {
        32
    } else if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    };
    format!("{tg:X}")
}

pub fn seq_sp(values: &[u32]) -> String {
    if values.is_empty() {
        return "0".into();
    }
    let min = values.iter().min().copied().unwrap_or(0);
    let max = values.iter().max().copied().unwrap_or(0);
    format!("{:X}-{:X}", min & 0xFF, max & 0xFF)
}

pub fn seq_gcd(values: &[u32]) -> String {
    if values.len() < 2 {
        return "1".into();
    }
    let mut diffs: Vec<u32> = values.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    diffs.retain(|&d| d > 0);
    if diffs.is_empty() {
        return "1".into();
    }
    let mut g = diffs[0];
    for &d in &diffs[1..] {
        g = gcd(g, d);
    }
    if g == 0 {
        "1".into()
    } else if g > 0xFFFF {
        format!(">{:X}", 0xFFFF)
    } else {
        format!("{g:X}")
    }
}

pub fn seq_isr(values: &[u32]) -> String {
    if values.len() < 2 {
        return "100".into();
    }
    let mut rates: Vec<u32> = values
        .windows(2)
        .map(|w| {
            let d = w[1].wrapping_sub(w[0]);
            if d == 0 {
                0
            } else {
                (0xFFFFFFFFu32 / d).min(0xFFFF)
            }
        })
        .collect();
    rates.retain(|&r| r > 0);
    if rates.is_empty() {
        return "100".into();
    }
    let min = rates.iter().min().copied().unwrap_or(100);
    let max = rates.iter().max().copied().unwrap_or(100);
    format!("{min:X}-{max:X}")
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

pub fn ack_class(seq: u32, ack: u32, our_seq: u32) -> String {
    if ack == 0 {
        return "Z".into();
    }
    let diff = ack.wrapping_sub(our_seq);
    if diff == 1 {
        "S".into()
    } else if diff > 1 {
        "S++".into()
    } else if ack == seq {
        "S".into()
    } else {
        "O".into()
    }
}

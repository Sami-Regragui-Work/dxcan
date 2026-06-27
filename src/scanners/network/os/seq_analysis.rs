use super::fingerprint::{seq_gcd, seq_isr, seq_sp};

pub struct SeqSamples {
    pub seqs: [u32; 6],
    pub ip_ids: [u16; 6],
    pub timestamps: [u32; 6],
    pub got: [bool; 6],
    pub count: usize,
}

impl SeqSamples {
    pub fn new() -> Self {
        Self {
            seqs: [0; 6],
            ip_ids: [0; 6],
            timestamps: [0; 6],
            got: [false; 6],
            count: 0,
        }
    }

    pub fn record(&mut self, idx: usize, seq: u32, ip_id: u16, ts: u32) {
        if idx >= 6 || self.got[idx] {
            return;
        }
        self.seqs[idx] = seq;
        self.ip_ids[idx] = ip_id;
        self.timestamps[idx] = ts;
        self.got[idx] = true;
        self.count += 1;
    }

    pub fn seq_values(&self) -> Vec<u32> {
        (0..6)
            .filter(|&i| self.got[i])
            .map(|i| self.seqs[i])
            .collect()
    }
}

pub fn fill_seq_fields(
    fp: &mut super::fingerprint::Fingerprint,
    samples: &SeqSamples,
    send_gap_ms: u64,
) {
    let values = samples.seq_values();
    if values.len() >= 2 {
        fp.set("SEQ", "SP", seq_sp(&values));
        fp.set("SEQ", "GCD", seq_gcd(&values));
        if send_gap_ms > 0 {
            let mut rates = Vec::new();
            for w in values.windows(2) {
                let diff = w[1].wrapping_sub(w[0]);
                if diff > 0 {
                    rates.push((diff as f64 * 1000.0 / send_gap_ms as f64) as u32);
                }
            }
            if !rates.is_empty() {
                let avg = rates.iter().sum::<u32>() / rates.len() as u32;
                let isr = if avg == 0 {
                    0
                } else {
                    let logv = (avg as f64).log2() * 8.0;
                    logv.round() as u32
                };
                fp.set("SEQ", "ISR", format!("{isr:X}"));
            }
        } else {
            fp.set("SEQ", "ISR", seq_isr(&values));
        }
    }
    if let Some(ti) = classify_ip_ids(&samples.ip_ids, &samples.got, 3) {
        fp.set("SEQ", "TI", ti);
    }
    if let Some(ts) = classify_timestamps(samples) {
        fp.set("SEQ", "TS", ts);
    }
}

pub fn fill_seq_ipid_fields(
    fp: &mut super::fingerprint::Fingerprint,
    tcp_open_ids: &[Option<u16>],
    tcp_closed_ids: &[Option<u16>],
    icmp_ids: &[Option<u16>],
) {
    if let Some(ci) = classify_ip_id_options(tcp_closed_ids, 2) {
        fp.set("SEQ", "CI", ci);
    }
    if let Some(ii) = classify_ip_id_options(icmp_ids, 2) {
        fp.set("SEQ", "II", ii);
    }
    if let (Some(ti), Some(ii)) = (
        classify_ip_id_options(tcp_open_ids, 3),
        classify_ip_id_options(icmp_ids, 2),
    ) {
        if matches!(ti.as_str(), "I" | "RI" | "BI") && matches!(ii.as_str(), "I" | "RI" | "BI") {
            let ss = if shared_ip_id_sequence(tcp_open_ids, icmp_ids) {
                "S"
            } else {
                "O"
            };
            fp.set("SEQ", "SS", ss);
        }
    }
}

fn classify_timestamps(samples: &SeqSamples) -> Option<String> {
    let mut any = false;
    let mut all_zero = true;
    for i in 0..6 {
        if !samples.got[i] {
            continue;
        }
        any = true;
        if samples.timestamps[i] != 0 {
            all_zero = false;
        }
    }
    if !any {
        return None;
    }
    if all_zero {
        return Some("0".into());
    }
    Some("A".into())
}

fn classify_ip_ids(ids: &[u16; 6], got: &[bool; 6], min: usize) -> Option<String> {
    let vals: Vec<u16> = (0..6).filter(|&i| got[i]).map(|i| ids[i]).collect();
    classify_ip_id_slice(&vals, min)
}

fn classify_ip_id_options(ids: &[Option<u16>], min: usize) -> Option<String> {
    let vals: Vec<u16> = ids.iter().filter_map(|v| *v).collect();
    classify_ip_id_slice(&vals, min)
}

fn classify_ip_id_slice(vals: &[u16], min: usize) -> Option<String> {
    if vals.len() < min {
        return None;
    }
    if vals.iter().all(|&v| v == 0) {
        return Some("Z".into());
    }
    if vals.windows(2).any(|w| w[1] as i32 - w[0] as i32 >= 20000) {
        return Some("RD".into());
    }
    if vals.iter().all(|&v| v == vals[0]) {
        return Some(format!("{:X}", vals[0]));
    }
    let diffs: Vec<i32> = vals.windows(2).map(|w| w[1] as i32 - w[0] as i32).collect();
    if diffs.iter().any(|&d| d.abs() > 1000 && d % 256 != 0) {
        return Some("RI".into());
    }
    if !diffs.is_empty()
        && diffs.iter().all(|&d| d > 0 && d % 256 == 0 && d <= 5120)
    {
        return Some("BI".into());
    }
    if diffs.iter().all(|&d| d > 0 && d < 10) {
        return Some("I".into());
    }
    None
}

fn shared_ip_id_sequence(tcp: &[Option<u16>], icmp: &[Option<u16>]) -> bool {
    let tcp_vals: Vec<u16> = tcp.iter().filter_map(|v| *v).collect();
    let icmp_vals: Vec<u16> = icmp.iter().filter_map(|v| *v).collect();
    if tcp_vals.len() < 2 || icmp_vals.is_empty() {
        return false;
    }
    let first = tcp_vals[0];
    let last = *tcp_vals.last().unwrap();
    let avg = (last as i32 - first as i32) / (tcp_vals.len() as i32 - 1).max(1);
    let icmp_first = icmp_vals[0];
    icmp_first < last.wrapping_add((avg * 3) as u16)
}

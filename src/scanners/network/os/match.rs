use super::db::{MatchPoints, OsEntry};
use super::fingerprint::Fingerprint;

#[derive(Clone)]
pub struct MatchResult {
    pub name: String,
    pub accuracy: u8,
    pub score: u32,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub os_gen: Option<String>,
    pub device_type: Option<String>,
    pub running: Option<String>,
    pub cpes: Vec<String>,
}

fn match_result_from_entry(entry: &OsEntry, accuracy: u8, score: u32) -> MatchResult {
    let primary = entry.primary_class();
    MatchResult {
        name: entry.name.clone(),
        accuracy,
        score,
        vendor: primary
            .and_then(|c| (!c.vendor.is_empty()).then(|| c.vendor.clone())),
        os_family: primary
            .and_then(|c| (!c.os_family.is_empty()).then(|| c.os_family.clone())),
        os_gen: primary.and_then(|c| (!c.os_gen.is_empty()).then(|| c.os_gen.clone())),
        device_type: primary
            .and_then(|c| (!c.device_type.is_empty()).then(|| c.device_type.clone())),
        running: entry.running_line(),
        cpes: entry.cpes.clone(),
    }
}

#[allow(dead_code)]
pub fn match_fingerprint(
    observed: &Fingerprint,
    match_points: &MatchPoints,
    entries: &[OsEntry],
) -> Option<MatchResult> {
    best_match_fingerprint(observed, match_points, entries, 85)
}

pub fn best_match_fingerprint(
    observed: &Fingerprint,
    match_points: &MatchPoints,
    entries: &[OsEntry],
    min_accuracy: u8,
) -> Option<MatchResult> {
    let candidates = collect_matches(observed, match_points, entries, min_accuracy);
    select_classified_match(candidates)
}

fn collect_matches(
    observed: &Fingerprint,
    match_points: &MatchPoints,
    entries: &[OsEntry],
    min_accuracy: u8,
) -> Vec<MatchResult> {
    let mut out = Vec::new();
    for entry in entries {
        let (score, max_score) = score_entry(observed, match_points, entry);
        if max_score == 0 {
            continue;
        }
        let accuracy = ((score as f64 / max_score as f64) * 100.0).round() as u8;
        if accuracy < min_accuracy {
            continue;
        }
        out.push(match_result_from_entry(entry, accuracy, score));
    }
    out
}

fn match_rank(a: &MatchResult, b: &MatchResult) -> std::cmp::Ordering {
    b.accuracy
        .cmp(&a.accuracy)
        .then(b.score.cmp(&a.score))
}

fn is_linux_family(m: &MatchResult) -> bool {
    if m
        .os_family
        .as_ref()
        .is_some_and(|f| f.eq_ignore_ascii_case("linux"))
    {
        return true;
    }
    let n = m.name.to_lowercase();
    n.starts_with("linux ") || n == "linux"
}

fn is_general_purpose(m: &MatchResult) -> bool {
    m.device_type
        .as_ref()
        .is_some_and(|d| d.eq_ignore_ascii_case("general purpose"))
}

fn is_niche_device(m: &MatchResult) -> bool {
    let Some(d) = m.device_type.as_ref() else {
        return false;
    };
    let d = d.to_lowercase();
    matches!(
        d.as_str(),
        "router"
            | "switch"
            | "bridge"
            | "wap"
            | "firewall"
            | "game console"
            | "media device"
            | "phone"
            | "power-device"
            | "printer"
            | "security-misc"
            | "specialized"
            | "storage-misc"
            | "telecom-misc"
            | "terminal"
            | "webcam"
    )
}

fn is_interval_name(name: &str) -> bool {
    name.contains(" - ")
}

fn same_os_lineage(top: &MatchResult, candidate: &MatchResult) -> bool {
    if top
        .os_family
        .as_ref()
        .is_some_and(|f| candidate.os_family.as_ref().is_some_and(|g| f == g))
    {
        return true;
    }
    let top_words: Vec<&str> = top.name.split_whitespace().collect();
    if top_words.len() >= 2 {
        let prefix = format!("{} {}", top_words[0], top_words[1]);
        return candidate.name.starts_with(&prefix);
    }
    candidate.name.starts_with(&top.name)
}

fn prefer_interval_over_point(top: MatchResult, candidates: &[MatchResult]) -> MatchResult {
    if is_interval_name(&top.name) {
        return top;
    }
    let band = if top.accuracy >= 90 { 2 } else { 8 };
    let mut best: Option<MatchResult> = None;
    for c in candidates {
        if top.accuracy.saturating_sub(c.accuracy) > band {
            continue;
        }
        if !is_interval_name(&c.name) || !same_os_lineage(&top, c) {
            continue;
        }
        match &best {
            None => best = Some(c.clone()),
            Some(prev) if match_rank(c, prev) == std::cmp::Ordering::Less => {
                best = Some(c.clone());
            }
            _ => {}
        }
    }
    best.unwrap_or(top)
}

fn select_classified_match(mut candidates: Vec<MatchResult>) -> Option<MatchResult> {
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(match_rank);
    let top = candidates[0].clone();

    let picked = if top.accuracy >= 90 && !is_niche_device(&top) {
        top
    } else if is_niche_device(&top) {
        let band = if top.accuracy >= 85 { 3 } else { 12 };
        let mut linux_candidates: Vec<MatchResult> = candidates
            .iter()
            .filter(|c| top.accuracy.saturating_sub(c.accuracy) <= band && is_linux_family(c))
            .cloned()
            .collect();
        if linux_candidates.is_empty() {
            top
        } else {
            linux_candidates.sort_by(|a, b| {
                match_rank(a, b)
                    .then_with(|| is_general_purpose(b).cmp(&is_general_purpose(a)))
            });
            linux_candidates[0].clone()
        }
    } else {
        top
    };

    Some(prefer_interval_over_point(picked, &candidates))
}

fn score_entry(observed: &Fingerprint, mp: &MatchPoints, entry: &OsEntry) -> (u32, u32) {
    let mut score = 0u32;
    let mut max_score = 0u32;

    for (test_name, weights) in &mp.weights {
        let obs_block = match observed.test_block(test_name) {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };
        let db_block = match entry.tests.get(test_name) {
            Some(b) if !b.fields.is_empty() => b,
            _ => continue,
        };

        for (field, weight) in weights {
            if *weight == 0 {
                continue;
            }
            let obs_val = obs_block.get(field).map(|s| s.as_str());
            let db_val = db_block.fields.get(field).map(|s| s.as_str());
            let (Some(o), Some(d)) = (obs_val, db_val) else {
                continue;
            };
            max_score += weight;
            if field_matches_observed(o, d) {
                score += weight;
            }
        }
    }

    (score, max_score)
}

fn field_matches_observed(observed: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return observed.is_empty();
    }
    field_matches(observed, pattern)
}

pub fn field_matches(observed: &str, pattern: &str) -> bool {
    if pattern.contains('|') && !pattern.starts_with('[') {
        return pattern
            .split('|')
            .any(|p| field_matches(observed, p.trim()));
    }
    if observed == pattern {
        return true;
    }
    if pattern == "N" && (observed == "N" || observed.is_empty()) {
        return true;
    }
    if pattern == "Y" && observed == "Y" {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix('<') {
        if let Some((num_str, tail)) = rest.split_once('&') {
            if let Ok(limit) = parse_hex_or_dec(num_str) {
                if let Ok(obs) = parse_hex_or_dec(observed) {
                    return obs < limit && field_matches(observed, tail);
                }
            }
        }
        if let Ok(limit) = parse_hex_or_dec(rest) {
            if let Ok(obs) = parse_hex_or_dec(observed) {
                return obs < limit;
            }
        }
    }
    if let Some(rest) = pattern.strip_prefix('>') {
        if let Ok(limit) = parse_hex_or_dec(rest) {
            if let Ok(obs) = parse_hex_or_dec(observed) {
                return obs > limit;
            }
        }
    }
    if pattern.contains('-') && !pattern.contains('|') {
        if let Some((lo, hi)) = pattern.split_once('-') {
            if let (Ok(lo_v), Ok(hi_v), Ok(obs)) = (
                parse_hex_or_dec(lo),
                parse_hex_or_dec(hi),
                parse_hex_or_dec(observed),
            ) {
                return obs >= lo_v && obs <= hi_v;
            }
        }
    }
    if pattern.contains('&') {
        return pattern
            .split('&')
            .all(|p| field_matches(observed, p.trim()));
    }
    if pattern.starts_with('=') {
        return observed == &pattern[1..];
    }
    false
}

fn parse_hex_or_dec(s: &str) -> Result<u32, ()> {
    let s = s.trim();
    if s.is_empty() {
        return Err(());
    }
    if let Ok(v) = u32::from_str_radix(s, 16) {
        return Ok(v);
    }
    s.parse::<u32>().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::network::os::db;
    use crate::scanners::network::os::fingerprint::Fingerprint;

    #[test]
    fn range_match() {
        assert!(field_matches("40", "3B-45"));
        assert!(field_matches("AS", "AS|AR"));
        assert!(field_matches("AR", "AS|AR"));
    }

    #[test]
    fn empty_pattern_requires_empty_observed() {
        assert!(field_matches_observed("", ""));
        assert!(!field_matches_observed("Y", ""));
    }

    #[test]
    fn prefers_linux_over_niche_router_at_similar_accuracy() {
        let candidates = vec![
            MatchResult {
                name: "MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)".into(),
                accuracy: 82,
                score: 100,
                vendor: Some("MikroTik".into()),
                os_family: Some("RouterOS".into()),
                os_gen: Some("7.X".into()),
                device_type: Some("router".into()),
                running: Some("RouterOS 7.X".into()),
                cpes: vec![],
            },
            MatchResult {
                name: "Linux 5.0 - 5.4".into(),
                accuracy: 78,
                score: 95,
                vendor: Some("Linux".into()),
                os_family: Some("Linux".into()),
                os_gen: Some("5.0 - 5.4".into()),
                device_type: Some("general purpose".into()),
                running: Some("Linux 5.0 - 5.4".into()),
                cpes: vec![],
            },
        ];
        let picked = select_classified_match(candidates).unwrap();
        assert!(picked.name.contains("Linux"));
        assert!(is_interval_name(&picked.name));
        assert_eq!(picked.device_type.as_deref(), Some("general purpose"));
    }

    fn load_fp_line(fp: &mut Fingerprint, line: &str) {
        let (test, rest) = line.split_once('(').unwrap();
        let inner = rest.strip_suffix(')').unwrap();
        for part in inner.split('%') {
            if let Some((k, v)) = part.split_once('=') {
                fp.set(test, k, v);
            }
        }
    }

    #[test]
    fn scanme_nmap_fingerprint_scores_like_nmap() {
        let db = db::database().expect("db");
        let mut fp = Fingerprint::default();
        for line in [
            "SEQ(SP=102%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)",
            "OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11NW7%O6=M578ST11)",
            "WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)",
            "ECN(R=Y%DF=Y%T=3F%W=FAF0%O=M578NNSNW7%CC=Y%Q=)",
            "T1(R=Y%DF=Y%T=3F%S=O%A=S+%F=AS%RD=0%Q=)",
            "T2(R=N)",
            "T3(R=N)",
            "T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)",
            "T5(R=Y%DF=Y%T=3F%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)",
            "T6(R=Y%DF=Y%T=3E%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)",
            "U1(R=Y%DF=N%T=3F%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)",
            "IE(R=Y%DFI=N%T=3F%CD=S)",
        ] {
            load_fp_line(&mut fp, line);
        }
        let m = best_match_fingerprint(&fp, &db.match_points, &db.entries, 85)
            .expect("expected >=85% Linux match");
        assert!(m.name.contains("Linux"), "got {}", m.name);
        assert!(
            is_interval_name(&m.name),
            "expected interval-style name, got {}",
            m.name
        );
        assert!(
            m.accuracy >= 90,
            "accuracy {} for {} (expected nmap-class >=90%)",
            m.accuracy,
            m.name
        );
    }
}

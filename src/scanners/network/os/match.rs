use super::db::{MatchPoints, OsEntry};
use super::fingerprint::Fingerprint;

pub struct MatchResult {
    pub name: String,
    pub accuracy: u8,
    pub score: u32,
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
    let mut best: Option<MatchResult> = None;

    for entry in entries {
        let (score, max_score) = score_entry(observed, match_points, entry);
        if max_score == 0 {
            continue;
        }
        let accuracy = ((score as f64 / max_score as f64) * 100.0).round() as u8;
        if accuracy < min_accuracy {
            continue;
        }
        let replace = best
            .as_ref()
            .map(|b| accuracy > b.accuracy || (accuracy == b.accuracy && score > b.score))
            .unwrap_or(true);
        if replace {
            best = Some(MatchResult {
                name: entry.name.clone(),
                accuracy,
                score,
            });
        }
    }

    best
}

fn score_entry(observed: &Fingerprint, mp: &MatchPoints, entry: &OsEntry) -> (u32, u32) {
    let mut score = 0u32;
    let mut max_score = 0u32;

    for (test_name, weights) in &mp.weights {
        let obs_block = observed.test_block(test_name);
        let db_block = entry.tests.get(test_name);

        for (field, weight) in weights {
            max_score += weight;
            let obs_val = obs_block.and_then(|b| b.get(field)).map(|s| s.as_str());
            let db_val = db_block
                .and_then(|b| b.fields.get(field))
                .map(|s| s.as_str());

            match (obs_val, db_val) {
                (Some(o), Some(d)) if field_matches(o, d) => score += weight,
                (None, Some(d)) if d == "N" || d.starts_with("N|") => score += weight,
                (Some("N"), Some(d)) if d.contains('N') || d.starts_with("R=N") => score += weight,
                _ => {}
            }
        }
    }

    (score, max_score)
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

    #[test]
    fn range_match() {
        assert!(field_matches("40", "3B-45"));
        assert!(field_matches("AS", "AS|AR"));
        assert!(field_matches("AR", "AS|AR"));
    }
}

use super::probe::HttpResponse;

pub fn same_fingerprint(a: &HttpResponse, b: &HttpResponse) -> bool {
    a.status == b.status && a.body_len == b.body_len && a.body_hash == b.body_hash
}

pub fn catchall_consensus(baselines: &[HttpResponse]) -> HttpResponse {
    modal_fingerprint(baselines).unwrap_or_else(|| baselines.first().expect("baseline").clone())
}

pub fn modal_fingerprint(responses: &[HttpResponse]) -> Option<HttpResponse> {
    if responses.is_empty() {
        return None;
    }
    let mut best = &responses[0];
    let mut best_count = 0usize;
    for r in responses {
        let count = responses.iter().filter(|x| same_fingerprint(x, r)).count();
        if count > best_count {
            best_count = count;
            best = r;
        }
    }
    Some(best.clone())
}

pub fn lengths_differ(a: usize, b: usize, margin: usize) -> bool {
    if a == b {
        return false;
    }
    if margin == 0 {
        return true;
    }
    a.abs_diff(b) > margin
}

pub fn length_only_diff(
    candidate: &HttpResponse,
    baseline: &HttpResponse,
    margin: usize,
) -> bool {
    candidate.status == baseline.status
        && lengths_differ(candidate.body_len, baseline.body_len, margin)
        && candidate.location == baseline.location
}

pub fn is_vhost_hit(
    candidate: &HttpResponse,
    baseline: &HttpResponse,
    match_hash: bool,
    length_margin: usize,
) -> bool {
    if candidate.status != baseline.status {
        return true;
    }
    if lengths_differ(candidate.body_len, baseline.body_len, length_margin) {
        return true;
    }
    if candidate.location != baseline.location {
        return true;
    }
    match_hash && candidate.body_hash != baseline.body_hash
}

pub fn passes_filters(
    candidate: &HttpResponse,
    ignore_lengths: &[usize],
    ignore_statuses: &[u16],
) -> bool {
    if ignore_statuses.contains(&candidate.status) {
        return false;
    }
    if ignore_lengths.contains(&candidate.body_len) {
        return false;
    }
    true
}

pub fn is_actionable_hit(
    candidate: &HttpResponse,
    catchall: &HttpResponse,
    match_hash: bool,
    length_margin: usize,
    ignore_lengths: &[usize],
    ignore_statuses: &[u16],
) -> bool {
    if !passes_filters(candidate, ignore_lengths, ignore_statuses) {
        return false;
    }
    is_vhost_hit(candidate, catchall, match_hash, length_margin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::probe::HttpResponse;

    fn resp(status: u16, len: usize, hash: u64, loc: Option<&str>) -> HttpResponse {
        HttpResponse {
            status,
            body_len: len,
            body_hash: hash,
            location: loc.map(str::to_string),
            latency_ms: 0.0,
        }
    }

    #[test]
    fn length_margin_tolerates_small_drift() {
        let b = resp(200, 1000, 1, None);
        let c = resp(200, 1030, 1, None);
        assert!(!is_vhost_hit(&c, &b, false, 50));
        assert!(is_vhost_hit(&c, &b, false, 0));
    }

    #[test]
    fn status_diff_is_hit() {
        let b = resp(404, 100, 1, None);
        let c = resp(200, 100, 1, None);
        assert!(is_vhost_hit(&c, &b, false, 0));
    }

    #[test]
    fn length_diff_is_hit() {
        let b = resp(200, 100, 1, None);
        let c = resp(200, 200, 1, None);
        assert!(is_vhost_hit(&c, &b, false, 0));
    }

    #[test]
    fn hash_only_not_hit_by_default() {
        let b = resp(200, 100, 42, None);
        let c = resp(200, 100, 99, None);
        assert!(!is_vhost_hit(&c, &b, false, 0));
        assert!(is_vhost_hit(&c, &b, true, 0));
    }

    #[test]
    fn identical_is_not_hit() {
        let b = resp(200, 100, 42, None);
        let c = resp(200, 100, 42, None);
        assert!(!is_vhost_hit(&c, &b, false, 0));
    }

    #[test]
    fn ignore_length_filters_candidate() {
        let catchall = resp(200, 100, 1, None);
        let c = resp(200, 200, 2, None);
        assert!(!is_actionable_hit(&c, &catchall, false, 0, &[200], &[]));
        assert!(is_actionable_hit(&c, &catchall, false, 0, &[], &[]));
    }

    #[test]
    fn consensus_picks_majority() {
        let b1 = resp(200, 100, 1, None);
        let b2 = resp(200, 100, 1, None);
        let b3 = resp(404, 50, 2, None);
        let c = catchall_consensus(&[b1.clone(), b2, b3]);
        assert_eq!(c.status, 200);
        assert_eq!(c.body_len, 100);
    }
}

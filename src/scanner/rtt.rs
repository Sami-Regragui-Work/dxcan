pub const MIN_SAMPLES: usize = 5;

pub struct RttTracker {
    pub srtt: f64,
    pub rttvar: f64,
    pub samples: usize,
}

impl RttTracker {
    pub fn new(initial_ms: f64) -> Self {
        Self {
            srtt: initial_ms,
            rttvar: initial_ms / 2.0,
            samples: 0,
        }
    }

    /// Feed a real RTT sample (only call for open/closed, not filtered).
    pub fn update(&mut self, rtt_ms: f64) {
        if self.samples == 0 {
            self.srtt = rtt_ms;
            self.rttvar = rtt_ms / 2.0;
        } else {
            let diff = (rtt_ms - self.srtt).abs();
            self.rttvar = self.rttvar + (diff - self.rttvar) / 4.0;
            self.srtt = self.srtt + (rtt_ms - self.srtt) / 8.0;
        }
        self.samples += 1;
    }

    /// Returns adaptive timeout in ms, or None if not enough samples yet.
    pub fn timeout_ms(&self) -> Option<f64> {
        if self.samples >= MIN_SAMPLES {
            Some((self.srtt + self.rttvar * 4.0).max(50.0))
        } else {
            None
        }
    }
}
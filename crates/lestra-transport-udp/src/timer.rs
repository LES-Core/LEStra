use std::time::{Duration, Instant};

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const INITIAL_RTO_MS: u64 = 250;
const MAX_RTO_MS: u64 = 2000;
const MAX_TRANSMISSIONS: u8 = 6;

const BACKPRESSURE_DELAY: Duration = Duration::from_millis(10);

/// Bounded retransmission schedule for one handshake flight.
///
/// The original handshake deadline is managed separately.
pub(crate) struct RetrySchedule {
    next_send: Instant,
    sent: u8,
    jitter_seed: [u8; 8],
}

impl RetrySchedule {
    pub(crate) fn new(now: Instant, jitter_seed: [u8; 8]) -> Self {
        Self {
            next_send: now,
            sent: 0,
            jitter_seed,
        }
    }

    pub(crate) fn is_due(&self, now: Instant) -> bool {
        self.sent < MAX_TRANSMISSIONS && now >= self.next_send
    }

    pub(crate) fn has_sent(&self) -> bool {
        self.sent != 0
    }

    /// Record a successful UDP transmission.
    pub(crate) fn on_sent(&mut self, now: Instant) {
        debug_assert!(self.sent < MAX_TRANSMISSIONS);

        let base_ms = (INITIAL_RTO_MS << self.sent.min(3)).min(MAX_RTO_MS);

        let sample = u64::from(self.jitter_seed[usize::from(self.sent)]);

        let jitter_ms = base_ms * sample / (4 * 255);

        self.sent += 1;

        self.next_send = now + Duration::from_millis(base_ms + jitter_ms);
    }

    /// Local socket backpressure does not consume
    /// the successful transmission budget.
    pub(crate) fn on_blocked(&mut self, now: Instant) {
        self.next_send = now + BACKPRESSURE_DELAY;
    }

    /// Start a new handshake flight.
    pub(crate) fn reset(&mut self, now: Instant) {
        self.sent = 0;
        self.next_send = now;
        self.jitter_seed.reverse();
    }

    #[cfg(test)]
    pub(crate) fn next_send_for_test(&self) -> Instant {
        self.next_send
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_is_bounded() {
        let start = Instant::now();
        let mut now = start;

        let mut timer = RetrySchedule::new(now, [0; 8]);

        for delay in [250, 500, 1000, 2000, 2000, 2000] {
            assert!(timer.is_due(now));

            timer.on_sent(now);

            assert_eq!(timer.next_send, now + Duration::from_millis(delay));

            now = timer.next_send;
        }

        assert!(!timer.is_due(now));
        assert_eq!(timer.sent, 6);
    }

    #[test]
    fn jitter_is_bounded() {
        let now = Instant::now();
        let mut timer = RetrySchedule::new(now, [255; 8]);

        timer.on_sent(now);

        assert_eq!(timer.next_send, now + Duration::from_millis(312));
    }

    #[test]
    fn backpressure_does_not_consume_retry_budget() {
        let now = Instant::now();
        let mut timer = RetrySchedule::new(now, [0; 8]);

        timer.on_blocked(now);

        assert!(!timer.has_sent());
        assert!(!timer.is_due(now));

        assert!(timer.is_due(now + Duration::from_millis(10)));
    }

    #[test]
    fn reset_starts_new_flight() {
        let now = Instant::now();
        let mut timer = RetrySchedule::new(now, [0; 8]);

        timer.on_sent(now);
        timer.reset(now);

        assert!(!timer.has_sent());
        assert!(timer.is_due(now));
    }
}

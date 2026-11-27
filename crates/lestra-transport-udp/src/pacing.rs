use std::time::Instant;

const CREDIT_SCALE: u128 = 1_000_000_000;

/// Fixed-rate UDP payload transmission budget.
///
/// Zero rate disables replenishment.
/// Zero burst prevents all transmissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacingLimit {
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
}

/// Server DATA transmission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPacingConfig {
    pub per_session: PacingLimit,
    pub global: PacingLimit,
}

impl Default for DataPacingConfig {
    fn default() -> Self {
        Self {
            per_session: PacingLimit {
                bytes_per_second: 64_000,
                burst_bytes: 4800,
            },

            global: PacingLimit {
                bytes_per_second: 1_000_000,
                burst_bytes: 48_000,
            },
        }
    }
}

/// Integer-based byte token bucket.
///
/// Fractional byte credits are preserved without
/// floating-point arithmetic.
pub(crate) struct BytePacer {
    limit: PacingLimit,
    credits: u128,
    last_refill: Instant,
}

impl BytePacer {
    pub(crate) fn new(limit: PacingLimit, now: Instant) -> Self {
        Self {
            limit,
            credits: u128::from(limit.burst_bytes) * CREDIT_SCALE,
            last_refill: now,
        }
    }

    fn capacity(&self) -> u128 {
        u128::from(self.limit.burst_bytes) * CREDIT_SCALE
    }

    fn refill(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };

        self.last_refill = now;

        let added = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.limit.bytes_per_second));

        self.credits = self.credits.saturating_add(added).min(self.capacity());
    }

    fn cost(bytes: usize) -> u128 {
        (bytes as u128).saturating_mul(CREDIT_SCALE)
    }

    /// Reserve transmission credit from one budget.
    pub(crate) fn reserve(&mut self, now: Instant, bytes: usize) -> bool {
        self.refill(now);

        let cost = Self::cost(bytes);

        if self.credits < cost {
            return false;
        }

        self.credits -= cost;

        true
    }

    /// Reserve transmission credit from both budgets.
    ///
    /// Neither budget is charged unless both have
    /// sufficient credit.
    ///
    /// Reservations are not refunded after socket errors.
    pub(crate) fn reserve_pair(&mut self, other: &mut Self, now: Instant, bytes: usize) -> bool {
        self.refill(now);
        other.refill(now);

        let cost = Self::cost(bytes);

        if self.credits < cost || other.credits < cost {
            return false;
        }

        self.credits -= cost;
        other.credits -= cost;

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pacer(rate: u64, burst: u64, now: Instant) -> BytePacer {
        BytePacer::new(
            PacingLimit {
                bytes_per_second: rate,
                burst_bytes: burst,
            },
            now,
        )
    }

    #[test]
    fn enforces_burst_capacity() {
        let now = Instant::now();

        let mut local = pacer(1000, 4800, now);
        let mut global = pacer(1000, 10_000, now);

        for _ in 0..4 {
            assert!(local.reserve_pair(&mut global, now, 1200,));
        }

        assert!(!local.reserve_pair(&mut global, now, 1,));
    }

    #[test]
    fn credits_refill_with_elapsed_time() {
        let now = Instant::now();

        let mut local = pacer(1000, 1200, now);
        let mut global = pacer(1000, 1200, now);

        assert!(local.reserve_pair(&mut global, now, 1200,));

        let early = now + Duration::from_millis(499);

        assert!(!local.reserve_pair(&mut global, early, 500,));

        let later = now + Duration::from_millis(500);

        assert!(local.reserve_pair(&mut global, later, 500,));
    }

    #[test]
    fn failed_global_check_preserves_local_credit() {
        let now = Instant::now();

        let mut local = pacer(0, 1200, now);
        let mut blocked = pacer(0, 0, now);
        let mut available = pacer(0, 1200, now);

        assert!(!local.reserve_pair(&mut blocked, now, 1200,));

        assert!(local.reserve_pair(&mut available, now, 1200,));
    }

    #[test]
    fn failed_local_check_preserves_global_credit() {
        let now = Instant::now();

        let mut blocked = pacer(0, 0, now);
        let mut available = pacer(0, 1200, now);
        let mut global = pacer(0, 1200, now);

        assert!(!blocked.reserve_pair(&mut global, now, 1200,));

        assert!(available.reserve_pair(&mut global, now, 1200,));
    }

    #[test]
    fn refill_cannot_exceed_burst_capacity() {
        let now = Instant::now();

        let mut local = pacer(1000, 1200, now);
        let mut global = pacer(1000, 1200, now);

        assert!(local.reserve_pair(&mut global, now, 1200,));

        let later = now + Duration::from_secs(3600);

        assert!(local.reserve_pair(&mut global, later, 1200,));

        assert!(!local.reserve_pair(&mut global, later, 1,));
    }

    #[test]
    fn backwards_time_does_not_grant_credit() {
        let now = Instant::now();

        let mut local = pacer(1000, 1200, now);
        let mut global = pacer(1000, 1200, now);

        let later = now + Duration::from_secs(1);

        assert!(local.reserve_pair(&mut global, later, 1200,));

        assert!(!local.reserve_pair(&mut global, now, 1,));

        assert!(!local.reserve_pair(&mut global, later, 1,));
    }

    #[test]
    fn single_pacer_enforces_transmission_budget() {
        let now = Instant::now();

        let mut pacer = pacer(1000, 1200, now);

        assert!(pacer.reserve(now, 1200));
        assert!(!pacer.reserve(now, 1));

        let later = now + Duration::from_millis(100);

        assert!(pacer.reserve(later, 100));
        assert!(!pacer.reserve(later, 1));
    }
}

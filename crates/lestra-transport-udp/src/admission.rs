use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use lestra_codec::{PacketType, decode_packet};
use lestra_crypto::INITIAL_SIZE;

const TOKEN_SCALE: u128 = 1_000_000_000;

/// Experimental INITIAL admission limits.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionLimits {
    pub global_rate: u32,
    pub global_burst: u32,

    pub per_ip_rate: u32,
    pub per_ip_burst: u32,

    pub max_tracked_ips: usize,
    pub max_pending_per_ip: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            global_rate: 512,
            global_burst: 256,

            per_ip_rate: 8,
            per_ip_burst: 16,

            max_tracked_ips: 8192,
            max_pending_per_ip: 16,
        }
    }
}

/// Normalize IPv4-mapped IPv6 addresses for IP quotas.
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
            Some(ipv4) => IpAddr::V4(ipv4),
            None => IpAddr::V6(ipv6),
        },

        IpAddr::V4(_) => ip,
    }
}

/// Integer-based token bucket.
///
/// One token is represented by TOKEN_SCALE credits.
/// Fractional refill is preserved without floating-point math.
struct TokenBucket {
    credits: u128,
    capacity: u128,
    rate: u32,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32, now: Instant) -> Self {
        let capacity = u128::from(burst) * TOKEN_SCALE;

        Self {
            credits: capacity,
            capacity,
            rate,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };

        self.last_refill = now;

        let added = elapsed.as_nanos().saturating_mul(u128::from(self.rate));

        self.credits = self.credits.saturating_add(added).min(self.capacity);
    }

    fn has_token(&self) -> bool {
        self.credits >= TOKEN_SCALE
    }

    fn consume(&mut self) {
        debug_assert!(self.has_token());

        self.credits -= TOKEN_SCALE;
    }

    fn is_full(&self) -> bool {
        self.credits == self.capacity
    }
}

/// Bounded rate limiter for incoming INITIAL packets.
///
/// This gate does not authenticate peers or reserve
/// session table capacity.
pub struct AdmissionGate {
    limits: AdmissionLimits,
    global: TokenBucket,
    sources: HashMap<IpAddr, TokenBucket>,
}

impl AdmissionGate {
    pub fn new(limits: AdmissionLimits, now: Instant) -> Self {
        Self {
            global: TokenBucket::new(limits.global_rate, limits.global_burst, now),

            limits,
            sources: HashMap::new(),
        }
    }

    pub fn limits(&self) -> AdmissionLimits {
        self.limits
    }

    pub fn tracked_ips(&self) -> usize {
        self.sources.len()
    }

    /// Check canonical INITIAL framing and rate limits.
    ///
    /// Call before performing Noise authentication.
    /// Successful admission does not imply authorization.
    pub fn allow_initial(&mut self, now: Instant, source: SocketAddr, bytes: &[u8]) -> bool {
        if bytes.len() != INITIAL_SIZE {
            return false;
        }

        let Ok(packet) = decode_packet(bytes) else {
            return false;
        };

        if packet.header.kind != PacketType::Initial {
            return false;
        }

        self.global.refill(now);

        if !self.global.has_token() {
            return false;
        }

        if self.limits.per_ip_burst == 0 {
            return false;
        }

        let ip = normalize_ip(source.ip());

        // Never evict active rate-limit state to make room
        // for an arbitrary new source.
        if self.sources.len() >= self.limits.max_tracked_ips && !self.sources.contains_key(&ip) {
            return false;
        }

        let bucket = self.sources.entry(ip).or_insert_with(|| {
            TokenBucket::new(self.limits.per_ip_rate, self.limits.per_ip_burst, now)
        });

        bucket.refill(now);

        if !bucket.has_token() {
            return false;
        }

        bucket.consume();
        self.global.consume();

        true
    }

    /// Remove fully replenished per-IP buckets.
    ///
    /// Recreating a removed bucket cannot grant extra
    /// tokens because it was already at full capacity.
    ///
    /// Call periodically from the transport maintenance loop.
    pub fn prune(&mut self, now: Instant) -> usize {
        let previous = self.sources.len();

        self.sources.retain(|_, bucket| {
            bucket.refill(now);

            !bucket.is_full()
        });

        previous - self.sources.len()
    }
}

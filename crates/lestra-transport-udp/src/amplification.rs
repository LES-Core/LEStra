use std::net::SocketAddr;

pub const AMPLIFICATION_FACTOR: usize = 3;

/// Conservative pre-validation UDP byte budget.
///
/// Bound to one original source IP and port.
/// Only actual received datagrams may grant credit.
///
/// The caller must not count the same received datagram
/// in multiple amplification budgets.
pub struct AmplificationBudget {
    source: SocketAddr,
    received_bytes: usize,
    reserved_bytes: usize,
}

impl AmplificationBudget {
    pub fn new(source: SocketAddr) -> Self {
        Self {
            source,
            received_bytes: 0,
            reserved_bytes: 0,
        }
    }

    pub fn source(&self) -> SocketAddr {
        self.source
    }

    pub fn received_bytes(&self) -> usize {
        self.received_bytes
    }

    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    pub fn remaining(&self) -> usize {
        self.received_bytes
            .saturating_mul(AMPLIFICATION_FACTOR)
            .saturating_sub(self.reserved_bytes)
    }

    /// Account for an actually received UDP datagram.
    ///
    /// A different source tuple cannot grant credit.
    pub fn record_received(&mut self, source: SocketAddr, len: usize) -> bool {
        if source != self.source {
            return false;
        }

        self.received_bytes = self.received_bytes.saturating_add(len);

        true
    }

    /// Reserve transmission credit before socket I/O.
    ///
    /// Reservations are intentionally not refunded.
    /// Failed sends therefore consume credit conservatively.
    pub fn try_reserve_send(&mut self, destination: SocketAddr, len: usize) -> bool {
        if destination != self.source || len > self.remaining() {
            return false;
        }

        let Some(total) = self.reserved_bytes.checked_add(len) else {
            return false;
        };

        self.reserved_bytes = total;

        true
    }
}

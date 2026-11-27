use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use lestra_codec::MAX_DATAGRAM_LEN;

use crate::ConnectionId;

const MAX_QUEUE_AGE: Duration = Duration::from_millis(100);

/// Result of attempting to flush pending DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushStatus {
    Idle,
    Blocked,
    Sent,
    Dropped,
}

/// Already encrypted datagram.
///
/// Retrying this packet must never invoke
/// the cryptographic layer again.
pub(crate) struct PendingDatagram {
    cid: ConnectionId,
    destination: SocketAddr,
    bytes: [u8; MAX_DATAGRAM_LEN],
    len: usize,
    queued_at: Instant,
}

impl PendingDatagram {
    pub(crate) fn new(
        cid: ConnectionId,
        destination: SocketAddr,
        bytes: [u8; MAX_DATAGRAM_LEN],
        len: usize,
        now: Instant,
    ) -> Self {
        assert!(len <= MAX_DATAGRAM_LEN);

        Self {
            cid,
            destination,
            bytes,
            len,
            queued_at: now,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Single-slot bounded ciphertext queue.
///
/// Never allocates heap memory and never
/// performs cryptographic operations.
#[derive(Default)]
pub(crate) struct SendQueue {
    pending: Option<PendingDatagram>,
}

impl SendQueue {
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn owner(&self) -> Option<ConnectionId> {
        self.pending.as_ref().map(|packet| packet.cid)
    }

    pub(crate) fn clear(&mut self) {
        self.pending = None;
    }

    pub(crate) fn discard_for(&mut self, cid: ConnectionId) {
        if self.owner() == Some(cid) {
            self.clear();
        }
    }

    pub(crate) fn discard_expired(&mut self, now: Instant) -> bool {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|packet| now.saturating_duration_since(packet.queued_at) >= MAX_QUEUE_AGE);

        if expired {
            self.clear();
        }

        expired
    }

    /// Submit an already encrypted packet.
    ///
    /// Socket backpressure retains the exact ciphertext.
    /// Success means either submitted or queued.
    pub(crate) fn submit(
        &mut self,
        packet: PendingDatagram,
        send: impl FnOnce(SocketAddr, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.is_pending() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DATA send queue is full",
            ));
        }

        match send(packet.destination, packet.bytes()) {
            Ok(()) => Ok(()),

            Err(error) if is_backpressure(&error) => {
                self.pending = Some(packet);

                Ok(())
            }

            Err(error) => Err(error),
        }
    }

    /// Attempt at most one pending transmission.
    pub(crate) fn flush(
        &mut self,
        now: Instant,
        send: impl FnOnce(SocketAddr, &[u8]) -> io::Result<()>,
    ) -> io::Result<FlushStatus> {
        if self.discard_expired(now) {
            return Ok(FlushStatus::Dropped);
        }

        let Some(packet) = self.pending.as_ref() else {
            return Ok(FlushStatus::Idle);
        };

        match send(packet.destination, packet.bytes()) {
            Ok(()) => {
                self.clear();

                Ok(FlushStatus::Sent)
            }

            Err(error) if is_backpressure(&error) => Ok(FlushStatus::Blocked),

            Err(error) => {
                self.clear();

                Err(error)
            }
        }
    }
}

fn is_backpressure(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 5000))
    }

    fn packet(cid: ConnectionId, now: Instant) -> PendingDatagram {
        PendingDatagram::new(
            cid,
            address(),
            [0xAB; MAX_DATAGRAM_LEN],
            MAX_DATAGRAM_LEN,
            now,
        )
    }

    fn blocked(_: SocketAddr, _: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    #[test]
    fn successful_send_does_not_allocate_queue_entry() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), |destination, bytes| {
            assert_eq!(destination, address());

            assert_eq!(bytes, &[0xAB; MAX_DATAGRAM_LEN]);

            Ok(())
        })?;

        assert!(!queue.is_pending());

        Ok(())
    }

    #[test]
    fn would_block_preserves_exact_ciphertext() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), blocked)?;

        assert!(queue.is_pending());

        assert_eq!(queue.flush(now, blocked)?, FlushStatus::Blocked);

        assert!(queue.is_pending());

        assert_eq!(
            queue.flush(now, |destination, bytes| {
                assert_eq!(destination, address());

                assert_eq!(bytes, &[0xAB; MAX_DATAGRAM_LEN]);

                Ok(())
            },)?,
            FlushStatus::Sent
        );

        assert!(!queue.is_pending());

        Ok(())
    }

    #[test]
    fn full_queue_rejects_new_packets() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), blocked)?;

        let error = queue
            .submit(packet([2; 8], now), |_, _| {
                panic!("full queue must not send")
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        assert_eq!(queue.owner(), Some([1; 8]));

        Ok(())
    }

    #[test]
    fn queued_packet_expires_at_exact_boundary() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), blocked)?;

        assert_eq!(
            queue.flush(now + Duration::from_millis(99), blocked,)?,
            FlushStatus::Blocked
        );

        assert_eq!(
            queue.flush(now + Duration::from_millis(100), |_, _| {
                panic!("expired packet must not send")
            },)?,
            FlushStatus::Dropped
        );

        assert!(!queue.is_pending());

        Ok(())
    }

    #[test]
    fn fatal_socket_error_discards_pending_packet() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), blocked)?;

        let error = queue
            .flush(now, |_, _| {
                Err(io::Error::from(io::ErrorKind::NetworkUnreachable))
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NetworkUnreachable);

        assert!(!queue.is_pending());

        Ok(())
    }

    #[test]
    fn session_removal_discards_only_its_own_packet() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), blocked)?;

        queue.discard_for([2; 8]);

        assert!(queue.is_pending());

        queue.discard_for([1; 8]);

        assert!(!queue.is_pending());

        Ok(())
    }

    #[test]
    fn interrupted_send_retains_packet() -> io::Result<()> {
        let now = Instant::now();
        let mut queue = SendQueue::default();

        queue.submit(packet([1; 8], now), |_, _| {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        })?;

        assert!(queue.is_pending());

        assert_eq!(queue.flush(now, |_, _| Ok(()))?, FlushStatus::Sent);

        assert!(!queue.is_pending());

        Ok(())
    }
}

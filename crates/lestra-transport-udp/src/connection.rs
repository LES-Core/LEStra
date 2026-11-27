use std::{io, net::SocketAddr, time::Instant};

use lestra_codec::{AEAD_TAG_LEN, HEADER_LEN, MAX_DATAGRAM_LEN, PacketType};

use lestra_crypto::{
    CLOSE_SIZE, EstablishedSession, MAX_DATA_SIZE, PacketProtectionError, ReceiveEvent,
};

use crate::send_queue::{FlushStatus, PendingDatagram, SendQueue};
use crate::{
    ClientConfig, ConnectionId, ExpirationReason, IncomingDatagram, SessionTimeouts, UdpIo,
    pacing::BytePacer,
};

/// Terminal reason for a managed connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionCloseReason {
    Local,
    Remote,
    Expired(ExpirationReason),
    ProtectionRetired,
}

/// Events produced by an established client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionEvent {
    Idle,
    Ignored,

    Data { len: usize },

    Closed { reason: ConnectionCloseReason },
}

/// Managed secure UDP connection.
///
/// Owns the UDP socket, cryptographic session,
/// transmission budget and lifetime policy.
///
/// Application datagrams remain unreliable
/// and unordered.
///
/// All operations are non-blocking.
pub struct UdpConnection {
    io: UdpIo,
    session: EstablishedSession,

    pacer: BytePacer,
    timeouts: SessionTimeouts,

    created_at: Instant,
    last_activity: Instant,

    close_reason: Option<ConnectionCloseReason>,
    send_queue: SendQueue,
}

impl UdpConnection {
    pub(crate) fn new(
        io: UdpIo,
        session: EstablishedSession,
        config: ClientConfig,
        established_at: Instant,
    ) -> Self {
        Self {
            io,
            session,

            pacer: BytePacer::new(config.pacing, established_at),

            timeouts: config.timeouts,

            created_at: established_at,
            last_activity: established_at,

            close_reason: None,
            send_queue: SendQueue::default(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.session.remote_endpoint()
    }

    pub fn local_receive_cid(&self) -> ConnectionId {
        self.session.local_receive_cid()
    }

    pub fn remote_receive_cid(&self) -> ConnectionId {
        self.session.remote_receive_cid()
    }

    pub fn is_closed(&self) -> bool {
        self.close_reason.is_some()
    }

    pub fn close_reason(&self) -> Option<ConnectionCloseReason> {
        self.close_reason
    }

    fn finish(&mut self, reason: ConnectionCloseReason) {
        self.session.close_local();
        self.send_queue.clear();

        if self.close_reason.is_none() {
            self.close_reason = Some(reason);
        }
    }

    fn sync_protection_state(&mut self) {
        if self.session.is_closed() {
            self.finish(ConnectionCloseReason::ProtectionRetired);
        }
    }

    fn expiration_reason(&self, now: Instant) -> Option<ExpirationReason> {
        if now.saturating_duration_since(self.created_at) >= self.timeouts.max_lifetime {
            return Some(ExpirationReason::MaxLifetime);
        }

        if now.saturating_duration_since(self.last_activity) >= self.timeouts.idle_timeout {
            return Some(ExpirationReason::IdleTimeout);
        }

        None
    }

    fn check_expiration(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }

        if let Some(reason) = self.expiration_reason(now) {
            self.finish(ConnectionCloseReason::Expired(reason));
        }
    }

    fn ensure_open(&mut self, now: Instant) -> io::Result<()> {
        self.check_expiration(now);

        match self.close_reason {
            None => Ok(()),

            Some(ConnectionCloseReason::Expired(_)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection has expired",
            )),

            Some(_) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection is closed",
            )),
        }
    }

    /// Encrypt and submit an unreliable DATA datagram.
    ///
    /// Success means that the packet was either submitted
    /// to the socket or retained in the bounded send queue.
    ///
    /// WouldBlock means that this new datagram was not
    /// accepted by the connection.
    pub fn send_data(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let now = Instant::now();

        self.ensure_open(now)?;

        if plaintext.len() > MAX_DATA_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "application datagram is oversized",
            ));
        }

        self.send_queue.discard_expired(now);

        // Check capacity before consuming pacing credit
        // or assigning a new packet number.
        if self.send_queue.is_pending() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DATA send queue is full",
            ));
        }

        let wire_len = HEADER_LEN + plaintext.len() + AEAD_TAG_LEN;

        if !self.pacer.reserve(now, wire_len) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DATA transmission rate exceeded",
            ));
        }

        let mut packet = [0_u8; MAX_DATAGRAM_LEN];

        let result = self.session.send_data(plaintext, &mut packet);

        self.sync_protection_state();

        let len = result.map_err(io::Error::other)?;

        let destination = self.remote_endpoint();

        // The final valid packet number may retire
        // the cryptographic session.
        //
        // Such a packet may be submitted immediately,
        // but must not be queued after retirement.
        if self.is_closed() {
            return self.io.send_to(destination, &packet[..len]);
        }

        let pending = PendingDatagram::new(self.local_receive_cid(), destination, packet, len, now);

        let io = &self.io;

        self.send_queue
            .submit(pending, |destination, bytes| io.send_to(destination, bytes))
    }

    /// Process at most one incoming datagram.
    ///
    /// Only authenticated DATA is exposed to the caller.
    /// Invalid packets do not refresh session activity.
    ///
    /// A closed connection continues to report its
    /// terminal reason on subsequent calls.
    pub fn poll(&mut self, output: &mut [u8; MAX_DATA_SIZE]) -> io::Result<ConnectionEvent> {
        self.poll_at(Instant::now(), output)
    }

    fn poll_at(
        &mut self,
        now: Instant,
        output: &mut [u8; MAX_DATA_SIZE],
    ) -> io::Result<ConnectionEvent> {
        self.check_expiration(now);

        if let Some(reason) = self.close_reason {
            return Ok(ConnectionEvent::Closed { reason });
        }

        self.poll_send_at(now)?;

        let incoming = match self.io.poll_recv() {
            Ok(incoming) => incoming,

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Ok(ConnectionEvent::Idle);
            }

            Err(error) => return Err(error),
        };

        let (source, header, bytes) = match incoming {
            Some(IncomingDatagram::Packet {
                source,
                header,
                bytes,
            }) => (source, header, bytes),

            Some(IncomingDatagram::Rejected { .. }) => {
                return Ok(ConnectionEvent::Ignored);
            }

            None => {
                return Ok(ConnectionEvent::Idle);
            }
        };

        // Cheap filtering before authentication.
        if source != self.session.remote_endpoint()
            || header.destination_connection_id != self.session.local_receive_cid()
            || !matches!(header.kind, PacketType::Data | PacketType::Close)
        {
            return Ok(ConnectionEvent::Ignored);
        }

        let result = self.session.receive(source, bytes, output);

        match result {
            Ok(ReceiveEvent::Data(len)) => {
                self.last_activity = self.last_activity.max(now);

                Ok(ConnectionEvent::Data { len })
            }

            Ok(ReceiveEvent::Closed) => {
                let reason = ConnectionCloseReason::Remote;

                self.finish(reason);

                Ok(ConnectionEvent::Closed { reason })
            }

            Err(PacketProtectionError::Noise(_) | PacketProtectionError::ReplayRejected) => {
                Ok(ConnectionEvent::Ignored)
            }

            Err(error) => {
                self.sync_protection_state();

                Err(io::Error::other(error))
            }
        }
    }

    /// Whether an encrypted DATA packet is awaiting
    /// socket transmission.
    pub fn has_pending_data(&self) -> bool {
        self.send_queue.is_pending()
    }

    /// Attempt one pending DATA transmission.
    pub fn poll_send(&mut self) -> io::Result<FlushStatus> {
        self.poll_send_at(Instant::now())
    }

    fn poll_send_at(&mut self, now: Instant) -> io::Result<FlushStatus> {
        let had_pending = self.send_queue.is_pending();

        self.check_expiration(now);

        if self.is_closed() {
            return Ok(if had_pending {
                FlushStatus::Dropped
            } else {
                FlushStatus::Idle
            });
        }

        let io = &self.io;

        self.send_queue
            .flush(now, |destination, bytes| io.send_to(destination, bytes))
    }

    /// Generate an authenticated CLOSE and retire
    /// the local connection.
    ///
    /// Local closure is permanent even when
    /// socket transmission fails.
    pub fn send_close(&mut self) -> io::Result<()> {
        self.ensure_open(Instant::now())?;

        let mut packet = [0_u8; CLOSE_SIZE];

        let result = self.session.send_close(&mut packet);

        let len = match result {
            Ok(len) => len,

            Err(error) => {
                self.sync_protection_state();

                return Err(io::Error::other(error));
            }
        };

        self.finish(ConnectionCloseReason::Local);

        self.io.send_to(self.remote_endpoint(), &packet[..len])
    }

    /// Permanently close without network transmission.
    pub fn close_local(&mut self) {
        self.finish(ConnectionCloseReason::Local);
    }
}

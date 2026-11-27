use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use lestra_codec::{CodecError, PacketType, decode_packet};

use lestra_crypto::{
    EstablishedSession, PacketProtectionError, READY_SIZE, ReceiveEvent, ServerAwaitingConfirm,
};

use crate::admission::normalize_ip;
use crate::timer::HANDSHAKE_TIMEOUT;

pub type ConnectionId = [u8; 8];

#[derive(Debug)]
pub enum SessionTableError {
    Codec(CodecError),
    Protection(PacketProtectionError),
    CapacityExceeded,
    PendingCapacityExceeded,
    ConnectionIdCollision,
    UnknownConnection,
}

impl fmt::Display for SessionTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(f, "invalid packet: {error}")
            }
            Self::Protection(error) => {
                write!(f, "packet protection error: {error}")
            }
            Self::CapacityExceeded => f.write_str("session table capacity exceeded"),
            Self::PendingCapacityExceeded => f.write_str("pending session capacity exceeded"),
            Self::ConnectionIdCollision => f.write_str("connection ID collision"),
            Self::UnknownConnection => f.write_str("unknown connection ID"),
        }
    }
}

impl std::error::Error for SessionTableError {}

impl From<CodecError> for SessionTableError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<PacketProtectionError> for SessionTableError {
    fn from(error: PacketProtectionError) -> Self {
        Self::Protection(error)
    }
}

/// Result of routing an incoming LEStra datagram.
#[derive(Debug, Eq, PartialEq)]
pub enum RouteEvent {
    Ignored,

    Established {
        cid: ConnectionId,
        destination: SocketAddr,
        ready: [u8; READY_SIZE],
    },

    RetryReady {
        cid: ConnectionId,
        destination: SocketAddr,
        ready: [u8; READY_SIZE],
    },

    Data {
        cid: ConnectionId,
        len: usize,
    },

    Closed {
        cid: ConnectionId,
    },
}

struct PendingEntry {
    session: ServerAwaitingConfirm,
    deadline: Instant,
}

struct EstablishedEntry {
    session: EstablishedSession,
    confirmation_deadline: Instant,
}

/// Bounded server-side session registry.
///
/// Routes packets by local receive CID.
///
/// This registry does not perform INITIAL admission,
/// amplification accounting or network I/O.
pub struct SessionTable {
    pending: HashMap<ConnectionId, PendingEntry>,
    established: HashMap<ConnectionId, EstablishedEntry>,

    max_sessions: usize,
    max_pending: usize,
}

impl SessionTable {
    pub fn new(max_sessions: usize, max_pending: usize) -> Self {
        Self {
            pending: HashMap::new(),
            established: HashMap::new(),
            max_sessions,
            max_pending,
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len() + self.established.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn established_len(&self) -> usize {
        self.established.len()
    }

    pub fn contains(&self, cid: ConnectionId) -> bool {
        self.pending.contains_key(&cid) || self.established.contains_key(&cid)
    }

    /// Check table capacity before performing expensive
    /// handshake operations.
    pub fn has_pending_capacity(&self) -> bool {
        self.len() < self.max_sessions && self.pending_len() < self.max_pending
    }

    /// Insert a previously admitted Noise handshake.
    ///
    /// The caller must enforce admission and authorization
    /// before constructing the pending session.
    pub fn insert_pending(
        &mut self,
        session: ServerAwaitingConfirm,
        now: Instant,
    ) -> Result<ConnectionId, SessionTableError> {
        let cid = session.local_receive_cid();

        if self.contains(cid) {
            return Err(SessionTableError::ConnectionIdCollision);
        }

        if self.len() >= self.max_sessions {
            return Err(SessionTableError::CapacityExceeded);
        }

        if self.pending_len() >= self.max_pending {
            return Err(SessionTableError::PendingCapacityExceeded);
        }

        self.pending.insert(
            cid,
            PendingEntry {
                session,
                deadline: now + HANDSHAKE_TIMEOUT,
            },
        );

        Ok(cid)
    }

    /// Route one incoming datagram.
    ///
    /// INITIAL admission is handled separately.
    /// No application data is exposed before authentication.
    pub fn route(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8],
        output: &mut [u8],
    ) -> Result<RouteEvent, SessionTableError> {
        let packet = decode_packet(bytes)?;

        let kind = packet.header.kind;
        let cid = packet.header.destination_connection_id;

        if kind == PacketType::Initial {
            return Ok(RouteEvent::Ignored);
        }

        if let Some(entry) = self.pending.get_mut(&cid) {
            if now >= entry.deadline {
                self.pending.remove(&cid);
                return Ok(RouteEvent::Ignored);
            }

            if source != entry.session.remote_endpoint() || kind != PacketType::Confirm {
                return Ok(RouteEvent::Ignored);
            }

            entry.session.accept_confirm(source, bytes)?;

            // Promote the same cryptographic state instead
            // of constructing a new session.
            let entry = self
                .pending
                .remove(&cid)
                .expect("authenticated pending entry");

            let (session, ready) = entry.session.into_established()?;

            self.established.insert(
                cid,
                EstablishedEntry {
                    session,
                    confirmation_deadline: entry.deadline,
                },
            );

            return Ok(RouteEvent::Established {
                cid,
                destination: source,
                ready,
            });
        }

        let Some(entry) = self.established.get_mut(&cid) else {
            return Ok(RouteEvent::Ignored);
        };

        if source != entry.session.remote_endpoint() {
            return Ok(RouteEvent::Ignored);
        }

        if now >= entry.confirmation_deadline {
            entry.session.discard_confirmation_cache();
        }

        if kind == PacketType::Confirm {
            return Ok(match entry.session.retry_ready(source, bytes) {
                Some(ready) => RouteEvent::RetryReady {
                    cid,
                    destination: source,
                    ready: *ready,
                },

                None => RouteEvent::Ignored,
            });
        }

        if !matches!(kind, PacketType::Data | PacketType::Close) {
            return Ok(RouteEvent::Ignored);
        }

        let result = entry.session.receive(source, bytes, output);

        let closed = entry.session.is_closed();

        if closed {
            self.established.remove(&cid);
        }

        match result? {
            ReceiveEvent::Data(len) => Ok(RouteEvent::Data { cid, len }),

            ReceiveEvent::Closed => Ok(RouteEvent::Closed { cid }),
        }
    }

    /// Protect an outgoing application datagram.
    ///
    /// Returns the destination endpoint and wire length.
    /// Does not perform network I/O.
    pub fn send_data(
        &mut self,
        cid: ConnectionId,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(SocketAddr, usize), SessionTableError> {
        self.send_with(cid, |session| session.send_data(plaintext, output))
    }

    /// Generate CLOSE and retire the local session.
    pub fn send_close(
        &mut self,
        cid: ConnectionId,
        output: &mut [u8],
    ) -> Result<(SocketAddr, usize), SessionTableError> {
        self.send_with(cid, |session| session.send_close(output))
    }

    fn send_with(
        &mut self,
        cid: ConnectionId,
        send: impl FnOnce(&mut EstablishedSession) -> Result<usize, PacketProtectionError>,
    ) -> Result<(SocketAddr, usize), SessionTableError> {
        let entry = self
            .established
            .get_mut(&cid)
            .ok_or(SessionTableError::UnknownConnection)?;

        let destination = entry.session.remote_endpoint();

        let result = send(&mut entry.session);

        if entry.session.is_closed() {
            self.established.remove(&cid);
        }

        Ok((destination, result?))
    }

    /// Retire a pending or established session.
    pub fn remove(&mut self, cid: ConnectionId) -> bool {
        self.pending.remove(&cid).is_some() || self.established.remove(&cid).is_some()
    }

    /// Expire pending handshakes and READY recovery caches.
    ///
    /// Established sessions are not evicted by this method.
    /// Returns the number of removed pending handshakes.
    pub fn expire_handshakes(&mut self, now: Instant) -> usize {
        let previous = self.pending.len();

        self.pending.retain(|_, entry| now < entry.deadline);

        for entry in self.established.values_mut() {
            if now >= entry.confirmation_deadline {
                entry.session.discard_confirmation_cache();
            }
        }

        previous - self.pending.len()
    }

    /// Count pending handshakes belonging to one IP address.
    pub fn pending_for_ip(&self, ip: IpAddr) -> usize {
        let ip = normalize_ip(ip);

        self.pending
            .values()
            .filter(|entry| normalize_ip(entry.session.remote_endpoint().ip()) == ip)
            .count()
    }

    pub fn is_pending(&self, cid: ConnectionId) -> bool {
        self.pending.contains_key(&cid)
    }

    /// Check global and per-IP pending capacity.
    pub fn has_pending_capacity_for_ip(&self, ip: IpAddr, limit: usize) -> bool {
        self.has_pending_capacity() && self.pending_for_ip(ip) < limit
    }
}

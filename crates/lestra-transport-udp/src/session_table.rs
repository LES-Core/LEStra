use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use lestra_codec::{CodecError, PacketType, decode_packet};

use lestra_crypto::{
    EstablishedSession, PacketProtectionError, READY_SIZE, ReceiveEvent, ServerAwaitingConfirm,
};

use crate::admission::normalize_ip;
use crate::config::SessionTimeouts;
use crate::timer::HANDSHAKE_TIMEOUT;

pub type ConnectionId = [u8; 8];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpirationReason {
    IdleTimeout,
    MaxLifetime,
}

#[derive(Debug)]
pub enum SessionTableError {
    Codec(CodecError),
    Protection(PacketProtectionError),
    CapacityExceeded,
    PendingCapacityExceeded,
    ConnectionIdCollision,
    UnknownConnection,
    SessionExpired,
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
            Self::SessionExpired => f.write_str("session lifetime has expired"),
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

    Expired {
        cid: ConnectionId,
        reason: ExpirationReason,
    },
}

struct PendingEntry {
    session: ServerAwaitingConfirm,
    deadline: Instant,
}

struct EstablishedEntry {
    session: EstablishedSession,
    confirmation_deadline: Instant,

    created_at: Instant,
    last_activity: Instant,
}

impl EstablishedEntry {
    fn expiration_reason(
        &self,
        now: Instant,
        timeouts: SessionTimeouts,
    ) -> Option<ExpirationReason> {
        if now.saturating_duration_since(self.created_at) >= timeouts.max_lifetime {
            return Some(ExpirationReason::MaxLifetime);
        }

        if now.saturating_duration_since(self.last_activity) >= timeouts.idle_timeout {
            return Some(ExpirationReason::IdleTimeout);
        }

        None
    }
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

    idle_index: BTreeSet<(Instant, ConnectionId)>,
    lifetime_index: BTreeSet<(Instant, ConnectionId)>,
    confirmation_index: BTreeSet<(Instant, ConnectionId)>,

    max_sessions: usize,
    max_pending: usize,

    timeouts: SessionTimeouts,
}

impl SessionTable {
    pub fn new(max_sessions: usize, max_pending: usize) -> Self {
        Self::with_timeouts(max_sessions, max_pending, SessionTimeouts::default())
    }

    pub fn with_timeouts(
        max_sessions: usize,
        max_pending: usize,
        timeouts: SessionTimeouts,
    ) -> Self {
        Self {
            pending: HashMap::new(),
            established: HashMap::new(),

            idle_index: BTreeSet::new(),
            lifetime_index: BTreeSet::new(),
            confirmation_index: BTreeSet::new(),

            max_sessions,
            max_pending,
            timeouts,
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
                    created_at: now,
                    last_activity: now,
                },
            );

            self.idle_index.insert((now, cid));
            self.lifetime_index.insert((now, cid));

            self.confirmation_index.insert((entry.deadline, cid));

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

        // Expired sessions cannot accept packets even if
        // periodic maintenance has not removed them yet.
        if let Some(reason) = entry.expiration_reason(now, self.timeouts) {
            self.remove_established(cid);

            return Ok(RouteEvent::Expired { cid, reason });
        }

        if now >= entry.confirmation_deadline {
            entry.session.discard_confirmation_cache();

            self.confirmation_index
                .remove(&(entry.confirmation_deadline, cid));
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

        // Refresh idle activity only after successful
        // authentication and replay validation.
        if matches!(&result, Ok(ReceiveEvent::Data(_))) {
            let previous = entry.last_activity;

            entry.last_activity = previous.max(now);

            self.idle_index.remove(&(previous, cid));

            self.idle_index.insert((entry.last_activity, cid));
        }

        let closed = entry.session.is_closed();

        if closed {
            self.remove_established(cid);
        }

        match result? {
            ReceiveEvent::Data(len) => Ok(RouteEvent::Data { cid, len }),

            ReceiveEvent::Closed => Ok(RouteEvent::Closed { cid }),
        }
    }

    /// Remove an established session and all timer indexes.
    fn remove_established(&mut self, cid: ConnectionId) -> bool {
        let Some(entry) = self.established.remove(&cid) else {
            return false;
        };

        self.idle_index.remove(&(entry.last_activity, cid));

        self.lifetime_index.remove(&(entry.created_at, cid));

        self.confirmation_index
            .remove(&(entry.confirmation_deadline, cid));

        true
    }

    /// Remove one expired established session.
    ///
    /// Returns at most one event per invocation.
    /// Absolute lifetime expiration takes precedence.
    pub fn pop_expired(&mut self, now: Instant) -> Option<(ConnectionId, ExpirationReason)> {
        let expired = self
            .lifetime_index
            .first()
            .filter(|(created, _)| {
                now.saturating_duration_since(*created) >= self.timeouts.max_lifetime
            })
            .map(|&(_, cid)| (cid, ExpirationReason::MaxLifetime))
            .or_else(|| {
                self.idle_index
                    .first()
                    .filter(|(activity, _)| {
                        now.saturating_duration_since(*activity) >= self.timeouts.idle_timeout
                    })
                    .map(|&(_, cid)| (cid, ExpirationReason::IdleTimeout))
            });

        if let Some((cid, _)) = expired {
            self.remove_established(cid);
        }

        expired
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

        if entry
            .expiration_reason(Instant::now(), self.timeouts)
            .is_some()
        {
            return Err(SessionTableError::SessionExpired);
        }

        let destination = entry.session.remote_endpoint();

        let result = send(&mut entry.session);

        if entry.session.is_closed() {
            self.remove_established(cid);
        }

        Ok((destination, result?))
    }

    /// Retire a pending or established session.
    pub fn remove(&mut self, cid: ConnectionId) -> bool {
        self.pending.remove(&cid).is_some() || self.remove_established(cid)
    }

    /// Expire pending handshakes and READY recovery caches.
    ///
    /// Established session lifetime is handled by pop_expired().
    pub fn expire_handshakes(&mut self, now: Instant) -> usize {
        let previous = self.pending.len();

        self.pending.retain(|_, entry| now < entry.deadline);

        while let Some(&(deadline, cid)) = self.confirmation_index.first() {
            if now < deadline {
                break;
            }

            self.confirmation_index.remove(&(deadline, cid));

            if let Some(entry) = self.established.get_mut(&cid) {
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

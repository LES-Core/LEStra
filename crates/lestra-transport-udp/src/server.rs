use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use lestra_codec::{MAX_DATAGRAM_LEN, PacketType};

use lestra_crypto::{INITIAL_SIZE, MAX_DATA_SIZE, READY_SIZE, RESPONSE_SIZE, ServerStart};

use crate::send_queue::{FlushStatus, PendingDatagram, SendQueue};
use crate::{
    AdmissionGate, ConnectionId, IncomingDatagram, RouteEvent, ServerConfig, SessionTable,
    SessionTableError, UdpIo,
    initial_cache::{InitialCache, InitialRecord, initial_key},
    pacing::BytePacer,
    session_table::ExpirationReason,
};

const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(250);

const MAX_CID_ATTEMPTS: usize = 16;

/// Public server events.
///
/// Application plaintext is available only
/// for authenticated Data events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerEvent {
    Idle,
    Ignored,
    Progress,

    Established {
        cid: ConnectionId,
        endpoint: SocketAddr,
    },

    Data {
        cid: ConnectionId,
        len: usize,
    },

    Expired {
        cid: ConnectionId,
        reason: ExpirationReason,
    },

    Closed {
        cid: ConnectionId,
    },
}

/// Internal action executed after releasing
/// the UDP receive buffer.
enum Action {
    Event(ServerEvent),

    Handshake {
        destination: SocketAddr,
        bytes: [u8; RESPONSE_SIZE],
    },

    Ready {
        cid: ConnectionId,
        destination: SocketAddr,
        bytes: [u8; READY_SIZE],
        first: bool,
    },
}

struct ServerState<'a> {
    server_private: &'a [u8; 32],
    allowed_client: [u8; 32],

    sessions: SessionTable,
    admission: AdmissionGate,
    initials: InitialCache,

    next_maintenance: Instant,
    global_pacer: BytePacer,
}

impl ServerState<'_> {
    fn maintenance(&mut self, now: Instant) {
        if now < self.next_maintenance {
            return;
        }

        self.sessions.expire_handshakes(now);
        self.initials.expire(now);
        self.admission.prune(now);

        self.next_maintenance = now + MAINTENANCE_INTERVAL;
    }

    fn generate_cid(&self) -> io::Result<ConnectionId> {
        for _ in 0..MAX_CID_ATTEMPTS {
            let mut cid = [0_u8; 8];

            getrandom::fill(&mut cid).map_err(|error| io::Error::other(error.to_string()))?;

            if cid != [0; 8] && !self.sessions.contains(cid) && !self.initials.contains_cid(cid) {
                return Ok(cid);
            }
        }

        Err(io::Error::other(
            "unable to allocate a unique connection ID",
        ))
    }

    fn handle_initial(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8],
    ) -> io::Result<Action> {
        let ignored = Action::Event(ServerEvent::Ignored);

        if !self.admission.allow_initial(now, source, bytes) {
            return Ok(ignored);
        }

        let Ok(initial) = <&[u8; INITIAL_SIZE]>::try_from(bytes) else {
            return Ok(ignored);
        };

        let key = initial_key(initial);

        // Handle duplicates before performing Noise IK.
        if let Some(record) = self.initials.get_mut(&key) {
            if !self.sessions.is_pending(record.cid) {
                return Ok(ignored);
            }

            return Ok(match record.retry(now, source, initial) {
                Some(response) => Action::Handshake {
                    destination: source,
                    bytes: response,
                },

                None => ignored,
            });
        }

        // Check all capacities before expensive work.
        if !self.initials.has_capacity()
            || !self.sessions.has_pending_capacity_for_ip(
                source.ip(),
                self.admission.limits().max_pending_per_ip,
            )
        {
            return Ok(ignored);
        }

        let cid = self.generate_cid()?;

        let pending = ServerStart::new(self.server_private, self.allowed_client, cid)
            .and_then(|server| server.accept_initial(source, initial));

        let Ok(pending) = pending else {
            // Do not respond to unauthorized clients
            // or invalid Noise messages.
            return Ok(ignored);
        };

        let response = *pending.response();

        let Ok(session) = pending.await_confirmation() else {
            return Ok(ignored);
        };

        let mut record = InitialRecord::new(cid, source, now, *initial, response);

        let Some(response) = record.reserve_response() else {
            return Ok(ignored);
        };

        if self.sessions.insert_pending(session, now).is_err() {
            return Ok(ignored);
        }

        if !self.initials.insert(key, record) {
            self.sessions.remove(cid);

            return Ok(ignored);
        }

        Ok(Action::Handshake {
            destination: source,
            bytes: response,
        })
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        source: SocketAddr,
        kind: PacketType,
        bytes: &[u8],
        output: &mut [u8; MAX_DATA_SIZE],
    ) -> io::Result<Action> {
        if kind == PacketType::Initial {
            return self.handle_initial(now, source, bytes);
        }

        // Bound confirmation processing and READY retries.
        if kind == PacketType::Confirm && !self.admission.allow_source(now, source) {
            return Ok(Action::Event(ServerEvent::Ignored));
        }

        let event = match self.sessions.route(now, source, bytes, output) {
            Ok(event) => event,

            // Invalid network input does not stop the server.
            Err(_) => {
                return Ok(Action::Event(ServerEvent::Ignored));
            }
        };

        Ok(match event {
            RouteEvent::Ignored => Action::Event(ServerEvent::Ignored),

            RouteEvent::Established {
                cid,
                destination,
                ready,
            } => Action::Ready {
                cid,
                destination,
                bytes: ready,
                first: true,
            },

            RouteEvent::RetryReady {
                cid,
                destination,
                ready,
            } => Action::Ready {
                cid,
                destination,
                bytes: ready,
                first: false,
            },

            RouteEvent::Data { cid, len } => Action::Event(ServerEvent::Data { cid, len }),

            RouteEvent::Expired { cid, reason } => {
                Action::Event(ServerEvent::Expired { cid, reason })
            }

            RouteEvent::Closed { cid } => Action::Event(ServerEvent::Closed { cid }),
        })
    }
}

/// Non-blocking native UDP server.
///
/// Currently authorizes one client static identity.
///
/// The caller drives poll() and provides application
/// receive buffers. No background threads are created.
pub struct UdpServer<'a> {
    io: UdpIo,
    state: ServerState<'a>,

    send_queue: SendQueue,
}

impl<'a> UdpServer<'a> {
    pub fn new(
        io: UdpIo,
        config: ServerConfig,
        server_private: &'a [u8; 32],
        allowed_client: [u8; 32],
    ) -> Self {
        let now = Instant::now();

        Self {
            io,
            state: ServerState {
                server_private,
                allowed_client,

                sessions: SessionTable::with_transport_limits(
                    config.max_sessions,
                    config.max_pending,
                    config.timeouts,
                    config.pacing.per_session,
                ),

                admission: AdmissionGate::new(config.admission, now),

                initials: InitialCache::new(config.max_initial_cache),

                next_maintenance: now,

                global_pacer: BytePacer::new(config.pacing.global, now),
            },
            send_queue: SendQueue::default(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn pending_len(&self) -> usize {
        self.state.sessions.pending_len()
    }

    pub fn established_len(&self) -> usize {
        self.state.sessions.established_len()
    }

    /// Process at most one incoming datagram
    /// and one corresponding control transmission.
    pub fn poll(&mut self, output: &mut [u8; MAX_DATA_SIZE]) -> io::Result<ServerEvent> {
        let now = Instant::now();

        self.state.maintenance(now);

        if let Some((cid, reason)) = self.state.sessions.pop_expired(now) {
            self.send_queue.discard_for(cid);

            return Ok(ServerEvent::Expired { cid, reason });
        }

        self.poll_send_at(now)?;

        let action = match self.io.poll_recv() {
            Ok(Some(IncomingDatagram::Packet {
                source,
                header,
                bytes,
            })) => self
                .state
                .handle_packet(now, source, header.kind, bytes, output)?,

            Ok(Some(IncomingDatagram::Rejected { .. })) => {
                return Ok(ServerEvent::Ignored);
            }

            Ok(None) => {
                return Ok(ServerEvent::Idle);
            }

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Ok(ServerEvent::Idle);
            }

            Err(error) => return Err(error),
        };

        self.execute(action)
    }

    pub fn has_pending_data(&self) -> bool {
        self.send_queue.is_pending()
    }

    fn discard_invalid_pending(&mut self, now: Instant) -> bool {
        if self.send_queue.discard_expired(now) {
            return true;
        }

        if let Some(cid) = self.send_queue.owner() {
            if !self.state.sessions.can_send_at(cid, now) {
                self.send_queue.clear();

                return true;
            }
        }

        false
    }

    /// Attempt one pending server DATA transmission.
    pub fn poll_send(&mut self) -> io::Result<FlushStatus> {
        self.poll_send_at(Instant::now())
    }

    fn poll_send_at(&mut self, now: Instant) -> io::Result<FlushStatus> {
        if self.discard_invalid_pending(now) {
            return Ok(FlushStatus::Dropped);
        }

        let io = &self.io;

        self.send_queue
            .flush(now, |destination, bytes| io.send_to(destination, bytes))
    }

    fn execute(&mut self, action: Action) -> io::Result<ServerEvent> {
        match action {
            Action::Event(event) => {
                match event {
                    ServerEvent::Closed { cid } | ServerEvent::Expired { cid, .. } => {
                        self.send_queue.discard_for(cid);
                    }

                    _ => {}
                }

                Ok(event)
            }

            Action::Handshake { destination, bytes } => {
                match self.io.send_to(destination, &bytes) {
                    Ok(()) => Ok(ServerEvent::Progress),

                    Err(error) if is_backpressure(&error) => Ok(ServerEvent::Ignored),

                    Err(error) => Err(error),
                }
            }

            Action::Ready {
                cid,
                destination,
                bytes,
                first,
            } => {
                match self.io.send_to(destination, &bytes) {
                    Ok(()) if first => Ok(ServerEvent::Established {
                        cid,
                        endpoint: destination,
                    }),

                    Ok(()) => Ok(ServerEvent::Progress),

                    Err(error) => {
                        // Never expose a new established
                        // session if its first READY
                        // could not be submitted to UDP.
                        if first {
                            self.state.sessions.remove(cid);
                        }

                        if is_backpressure(&error) {
                            Ok(ServerEvent::Ignored)
                        } else {
                            Err(error)
                        }
                    }
                }
            }
        }
    }

    /// Encrypt and submit an unreliable DATA datagram.
    ///
    /// Success means submitted or retained in the bounded
    /// ciphertext queue. DATA delivery is not guaranteed.
    pub fn send_data(&mut self, cid: ConnectionId, plaintext: &[u8]) -> io::Result<()> {
        let now = Instant::now();

        self.discard_invalid_pending(now);

        // Never consume a packet number when the
        // shared socket queue is already occupied.
        if self.send_queue.is_pending() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DATA send queue is full",
            ));
        }

        let mut packet = [0_u8; MAX_DATAGRAM_LEN];

        let (destination, len) = self
            .state
            .sessions
            .send_data_paced(
                now,
                cid,
                plaintext,
                &mut packet,
                &mut self.state.global_pacer,
            )
            .map_err(|error| match error {
                SessionTableError::RateLimited => io::Error::new(io::ErrorKind::WouldBlock, error),

                _ => io::Error::other(error),
            })?;

        // A final packet may have retired the session
        // because of packet number exhaustion.
        if !self.state.sessions.can_send_at(cid, now) {
            return self.io.send_to(destination, &packet[..len]);
        }

        let pending = PendingDatagram::new(cid, destination, packet, len, now);

        let io = &self.io;

        self.send_queue
            .submit(pending, |destination, bytes| io.send_to(destination, bytes))
    }

    /// Generate CLOSE and retire the local session.
    ///
    /// The local session remains closed even if UDP
    /// transmission fails.
    pub fn send_close(&mut self, cid: ConnectionId) -> io::Result<()> {
        let mut packet = [0_u8; MAX_DATAGRAM_LEN];

        let (destination, len) = self
            .state
            .sessions
            .send_close(cid, &mut packet)
            .map_err(io::Error::other)?;

        self.send_queue.discard_for(cid);

        self.io.send_to(destination, &packet[..len])
    }

    /// Retire a connection without sending CLOSE.
    pub fn disconnect(&mut self, cid: ConnectionId) -> bool {
        self.send_queue.discard_for(cid);

        self.state.sessions.remove(cid)
    }
}

fn is_backpressure(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

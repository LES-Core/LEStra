use std::{fmt, io, net::SocketAddr, time::Instant};

use lestra_codec::PacketType;

use lestra_crypto::{
    ClientAwaitingReady, ClientPending, ClientStart, EstablishedSession, HandshakeError,
    PacketProtectionError,
};

use crate::{
    IncomingDatagram, UdpIo,
    timer::{HANDSHAKE_TIMEOUT, RetrySchedule},
};

#[derive(Debug)]
pub enum ConnectError {
    Io(io::Error),
    Handshake(HandshakeError),
    Protection(PacketProtectionError),
    Timeout,
    NotEstablished,
    AttemptFailed,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => {
                write!(f, "UDP I/O error: {error}")
            }
            Self::Handshake(error) => {
                write!(f, "handshake error: {error}")
            }
            Self::Protection(error) => {
                write!(f, "packet protection error: {error}")
            }
            Self::Timeout => f.write_str("handshake deadline exceeded"),
            Self::NotEstablished => f.write_str("session is not established"),
            Self::AttemptFailed => f.write_str("connection attempt has failed"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<io::Error> for ConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HandshakeError> for ConnectError {
    fn from(error: HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

impl From<PacketProtectionError> for ConnectError {
    fn from(error: PacketProtectionError) -> Self {
        Self::Protection(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectStatus {
    Pending,
    Established,
}

enum ClientState {
    Initial(ClientPending),
    Confirm(ClientAwaitingReady),
    Established(EstablishedSession),
    Failed,
}

/// Non-blocking client handshake driver.
///
/// Owns exactly one connection attempt and its UDP socket.
/// Does not spawn threads or perform blocking waits.
///
/// The caller must provide fresh, unpredictable receive CIDs.
pub struct UdpClient {
    io: UdpIo,
    server: SocketAddr,
    local_cid: [u8; 8],

    state: ClientState,
    retry: RetrySchedule,
    deadline: Instant,
}

impl UdpClient {
    /// Prepare a fresh connection attempt.
    ///
    /// The first INITIAL is transmitted by poll().
    pub fn connect(
        io: UdpIo,
        server: SocketAddr,
        client_static_private: &[u8; 32],
        pinned_server_static: &[u8; 32],
        local_cid: [u8; 8],
    ) -> Result<Self, ConnectError> {
        let pending = ClientStart::new(
            client_static_private,
            pinned_server_static,
            local_cid,
            server,
        )?
        .start()?;

        let now = Instant::now();

        Ok(Self {
            io,
            server,
            local_cid,
            state: ClientState::Initial(pending),
            retry: RetrySchedule::new(now, local_cid),
            deadline: now + HANDSHAKE_TIMEOUT,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.server
    }

    /// Perform one bounded unit of handshake progress.
    ///
    /// Processes at most one outgoing transmission
    /// and one incoming datagram.
    pub fn poll(&mut self) -> Result<ConnectStatus, ConnectError> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&mut self, now: Instant) -> Result<ConnectStatus, ConnectError> {
        let result = self.poll_inner(now);

        if result.is_err() {
            self.state = ClientState::Failed;
        }

        result
    }

    fn poll_inner(&mut self, now: Instant) -> Result<ConnectStatus, ConnectError> {
        match &self.state {
            ClientState::Established(_) => {
                return Ok(ConnectStatus::Established);
            }

            ClientState::Failed => {
                return Err(ConnectError::AttemptFailed);
            }

            _ => {}
        }

        if now >= self.deadline {
            return Err(ConnectError::Timeout);
        }

        // Send only previously generated handshake bytes.
        if self.retry.is_due(now) {
            let bytes: &[u8] = match &self.state {
                ClientState::Initial(pending) => pending.initial(),

                ClientState::Confirm(pending) => pending.confirm(),

                _ => unreachable!("pending handshake state"),
            };

            match self.io.send_to(self.server, bytes) {
                Ok(()) => self.retry.on_sent(now),

                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    self.retry.on_blocked(now);
                }

                Err(error) => return Err(error.into()),
            }
        }

        // Never accept a response before sending
        // the corresponding handshake flight.
        if !self.retry.has_sent() {
            return Ok(ConnectStatus::Pending);
        }

        let incoming = match self.io.poll_recv() {
            Ok(incoming) => incoming,

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Ok(ConnectStatus::Pending);
            }

            Err(error) => return Err(error.into()),
        };

        let Some(IncomingDatagram::Packet {
            source,
            header,
            bytes,
        }) = incoming
        else {
            return Ok(ConnectStatus::Pending);
        };

        // Cheap filtering before cryptographic work.
        if source != self.server || header.destination_connection_id != self.local_cid {
            return Ok(ConnectStatus::Pending);
        }

        match header.kind {
            PacketType::Handshake if matches!(&self.state, ClientState::Initial(_)) => {
                let ClientState::Initial(pending) =
                    std::mem::replace(&mut self.state, ClientState::Failed)
                else {
                    unreachable!("initial handshake state");
                };

                let pending = pending
                    .accept_response(source, bytes)?
                    .start_confirmation()?;

                self.state = ClientState::Confirm(pending);

                self.retry.reset(now);

                Ok(ConnectStatus::Pending)
            }

            PacketType::Ready => {
                let ClientState::Confirm(pending) = &mut self.state else {
                    return Ok(ConnectStatus::Pending);
                };

                match pending.accept_ready(source, bytes) {
                    Ok(()) => {}

                    // Authentication failures do not
                    // destroy the pending READY state.
                    Err(PacketProtectionError::Noise(_)) => {
                        return Ok(ConnectStatus::Pending);
                    }

                    Err(error) => return Err(error.into()),
                }

                let ClientState::Confirm(pending) =
                    std::mem::replace(&mut self.state, ClientState::Failed)
                else {
                    unreachable!("confirmation state");
                };

                self.state = ClientState::Established(pending.into_established()?);

                Ok(ConnectStatus::Established)
            }

            // Ignore premature DATA, unrelated control packets,
            // and duplicate HANDSHAKE messages.
            // Timer-driven CONFIRM retries remain available.
            _ => Ok(ConnectStatus::Pending),
        }
    }

    /// Consume the handshake driver and return the socket
    /// together with the authenticated session.
    pub fn into_established(self) -> Result<(UdpIo, EstablishedSession), ConnectError> {
        match self.state {
            ClientState::Established(session) => Ok((self.io, session)),

            _ => Err(ConnectError::NotEstablished),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{net::UdpSocket, thread, time::Duration};

    use lestra_codec::{MAX_DATAGRAM_LEN, decode_packet};

    use lestra_crypto::{ClientStart, MAX_DATA_SIZE, ReceiveEvent, ServerStart};

    use snow::{Builder, Keypair, params::NoiseParams};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn keys() -> Result<(Keypair, Keypair), snow::Error> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

        let builder = Builder::new(params);

        Ok((builder.generate_keypair()?, builder.generate_keypair()?))
    }

    fn addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    fn receive_wire(socket: &UdpSocket) -> io::Result<Vec<u8>> {
        let mut buffer = [0_u8; MAX_DATAGRAM_LEN + 1];

        let (len, _) = socket.recv_from(&mut buffer)?;

        Ok(buffer[..len].to_vec())
    }

    fn poll_until(
        client: &mut UdpClient,
        now: Instant,
        condition: impl Fn(&ClientState) -> bool,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(3);

        loop {
            client.poll_at(now)?;

            if condition(&client.state) {
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "test handshake timeout").into(),
                );
            }

            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn client_recovers_lost_initial_and_ready() -> TestResult {
        let (client_key, server_key) = keys()?;

        let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;

        let client_public: [u8; 32] = client_key.public.as_slice().try_into()?;

        let server_private: [u8; 32] = server_key.private.as_slice().try_into()?;

        let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

        let server_socket = UdpSocket::bind(addr())?;

        server_socket.set_read_timeout(Some(Duration::from_secs(3)))?;

        let server_addr = server_socket.local_addr()?;

        let mut client = UdpClient::connect(
            UdpIo::bind(addr())?,
            server_addr,
            &client_private,
            &server_public,
            [1; 8],
        )?;

        let client_addr = client.local_addr()?;

        let start = client.retry.next_send_for_test();

        // Send INITIAL, then simulate packet loss.
        client.poll_at(start)?;

        let initial = receive_wire(&server_socket)?;

        assert_eq!(decode_packet(&initial)?.header.kind, PacketType::Initial);

        // Retry INITIAL after the retransmission timeout.
        let now = start + Duration::from_millis(350);

        client.poll_at(now)?;

        let repeated = receive_wire(&server_socket)?;

        assert_eq!(initial, repeated);

        let server = ServerStart::new(&server_private, client_public, [2; 8])?
            .accept_initial(client_addr, &repeated)?;

        server_socket.send_to(server.response(), client_addr)?;

        poll_until(&mut client, now, |state| {
            matches!(state, ClientState::Confirm(_))
        })?;

        let mut server = server.await_confirmation()?;

        // Send CONFIRM.
        client.poll_at(now)?;

        let confirm = receive_wire(&server_socket)?;

        assert_eq!(decode_packet(&confirm)?.header.kind, PacketType::Confirm);

        server.accept_confirm(client_addr, &confirm)?;

        let (mut server, ready) = server.into_established()?;

        // Simulate lost READY.
        let now = now + Duration::from_millis(350);

        client.poll_at(now)?;

        let repeated = receive_wire(&server_socket)?;

        assert_eq!(confirm, repeated);

        let retried_ready = server
            .retry_ready(client_addr, &repeated)
            .expect("cached READY");

        assert_eq!(retried_ready, &ready);

        // A forged READY must not destroy the attempt.
        let mut forged = ready;
        *forged.last_mut().unwrap() ^= 1;

        server_socket.send_to(&forged, client_addr)?;

        // Poll while still expecting READY.
        assert_eq!(client.poll_at(now)?, ConnectStatus::Pending);

        server_socket.send_to(&ready, client_addr)?;

        poll_until(&mut client, now, |state| {
            matches!(state, ClientState::Established(_))
        })?;

        let (io, mut session) = client.into_established()?;

        let mut packet = [0_u8; MAX_DATAGRAM_LEN];

        let len = session.send_data(b"LEStra", &mut packet)?;

        io.send_to(server_addr, &packet[..len])?;

        let data = receive_wire(&server_socket)?;

        let mut plaintext = [0_u8; MAX_DATA_SIZE];

        assert_eq!(
            server.receive(client_addr, &data, &mut plaintext,)?,
            ReceiveEvent::Data(6)
        );

        assert_eq!(&plaintext[..6], b"LEStra");

        Ok(())
    }

    #[test]
    fn handshake_expires_without_response() -> TestResult {
        let (client_key, server_key) = keys()?;

        let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;

        let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

        let server = UdpSocket::bind(addr())?;

        let mut client = UdpClient::connect(
            UdpIo::bind(addr())?,
            server.local_addr()?,
            &client_private,
            &server_public,
            [1; 8],
        )?;

        let deadline = client.deadline;

        assert!(matches!(
            client.poll_at(deadline),
            Err(ConnectError::Timeout)
        ));

        assert!(matches!(&client.state, ClientState::Failed));

        assert!(matches!(client.poll(), Err(ConnectError::AttemptFailed)));

        assert!(matches!(
            client.into_established(),
            Err(ConnectError::NotEstablished)
        ));

        Ok(())
    }
}

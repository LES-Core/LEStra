use std::net::SocketAddr;

use lestra_codec::v2::{ACK_PLAINTEXT_LEN, AckFrame, PacketType};

use crate::{
    CONFIRM_SIZE, PacketProtectionError, READY_SIZE, RESPONSE_SIZE, ServerPendingConfirmation,
    VerifiedNoise, WireProfile, aead::PacketProtection,
};

const MAX_READY_RETRIES: u8 = 5;

/// Client waiting for an authenticated READY packet.
pub struct ClientAwaitingReady {
    protection: PacketProtection,
    confirm: [u8; CONFIRM_SIZE],
    ready_received: bool,
}

/// Server waiting for an authenticated CONFIRM packet.
pub struct ServerAwaitingConfirm {
    protection: PacketProtection,
    response: [u8; RESPONSE_SIZE],
    confirmation: Option<ServerConfirmationCache>,
}

/// Bounded cache for idempotent handshake recovery.
struct ServerConfirmationCache {
    confirm: [u8; CONFIRM_SIZE],
    ready: [u8; READY_SIZE],
    retries_remaining: u8,
}

/// Event produced by an authenticated incoming packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveEvent {
    /// Number of plaintext bytes written to the output buffer.
    Data(usize),

    /// The remote peer authenticated a CLOSE packet.
    Closed,
}

/// Cryptographically established LEStra session.
///
/// Application datagrams are unreliable and unordered.
/// A successful send operation does not guarantee delivery.
///
/// Closing the session permanently discards its packet protection
/// state and handshake recovery cache.
pub struct EstablishedSession {
    protection: Option<PacketProtection>,
    confirmation: Option<ServerConfirmationCache>,

    local_receive_cid: [u8; 8],
    remote_receive_cid: [u8; 8],
    remote_endpoint: SocketAddr,
    profile: WireProfile,
}

impl VerifiedNoise {
    /// Consume the verified initiator handshake and generate CONFIRM.
    pub fn start_confirmation(self) -> Result<ClientAwaitingReady, PacketProtectionError> {
        let mut protection = PacketProtection::from_verified(self)?;
        let mut confirm = [0_u8; CONFIRM_SIZE];

        protection.seal(PacketType::Confirm, &[], &mut confirm)?;

        Ok(ClientAwaitingReady {
            protection,
            confirm,
            ready_received: false,
        })
    }
}

impl ClientAwaitingReady {
    /// Returns immutable CONFIRM bytes for transmission or retry.
    pub fn confirm(&self) -> &[u8; CONFIRM_SIZE] {
        &self.confirm
    }

    pub fn local_receive_cid(&self) -> [u8; 8] {
        self.protection.local_receive_cid
    }

    pub fn remote_receive_cid(&self) -> [u8; 8] {
        self.protection.remote_receive_cid
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.protection.remote_endpoint
    }

    pub fn profile(&self) -> WireProfile {
        self.protection.profile
    }

    /// Authenticate READY without destroying the pending state
    /// on invalid network input.
    pub fn accept_ready(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), PacketProtectionError> {
        self.protection
            .open(source, PacketType::Ready, bytes, &mut [])?;

        self.ready_received = true;

        Ok(())
    }

    /// Establish the client session only after authenticated READY.
    pub fn into_established(self) -> Result<EstablishedSession, PacketProtectionError> {
        if !self.ready_received {
            return Err(PacketProtectionError::ConfirmationRequired);
        }

        Ok(EstablishedSession::new(self.protection, None))
    }
}

impl ServerPendingConfirmation {
    /// Consume the completed Noise responder handshake.
    pub fn await_confirmation(self) -> Result<ServerAwaitingConfirm, PacketProtectionError> {
        Ok(ServerAwaitingConfirm {
            protection: PacketProtection::from_verified(self.verified)?,
            response: self.response,
            confirmation: None,
        })
    }
}

impl ServerAwaitingConfirm {
    /// Cached HANDSHAKE bytes for bounded retransmission.
    pub fn response(&self) -> &[u8; RESPONSE_SIZE] {
        &self.response
    }

    pub fn local_receive_cid(&self) -> [u8; 8] {
        self.protection.local_receive_cid
    }

    pub fn remote_receive_cid(&self) -> [u8; 8] {
        self.protection.remote_receive_cid
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.protection.remote_endpoint
    }

    pub fn profile(&self) -> WireProfile {
        self.protection.profile
    }

    /// Authenticate CONFIRM and generate READY exactly once.
    ///
    /// Invalid incoming packets do not destroy this state.
    /// A failure during READY encryption requires abandoning
    /// the handshake.
    pub fn accept_confirm(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), PacketProtectionError> {
        if self.confirmation.is_some() {
            return Err(PacketProtectionError::ReplayRejected);
        }

        self.protection
            .open(source, PacketType::Confirm, bytes, &mut [])?;

        let confirm: [u8; CONFIRM_SIZE] = bytes
            .try_into()
            .expect("authenticated CONFIRM has a fixed size");

        let mut ready = [0_u8; READY_SIZE];

        self.protection.seal(PacketType::Ready, &[], &mut ready)?;

        self.confirmation = Some(ServerConfirmationCache {
            confirm,
            ready,
            retries_remaining: MAX_READY_RETRIES,
        });

        Ok(())
    }

    /// Establish the server session and return the initial READY.
    pub fn into_established(
        self,
    ) -> Result<(EstablishedSession, [u8; READY_SIZE]), PacketProtectionError> {
        if self.protection.profile == WireProfile::V2 {
            return Err(PacketProtectionError::ReadySubmissionRequired);
        }

        let confirmation = self
            .confirmation
            .ok_or(PacketProtectionError::ConfirmationRequired)?;

        let ready = confirmation.ready;

        Ok((
            EstablishedSession::new(self.protection, Some(confirmation)),
            ready,
        ))
    }

    /// Return the cached READY after authenticating CONFIRM.
    pub fn ready(&self) -> Option<&[u8; READY_SIZE]> {
        self.confirmation
            .as_ref()
            .map(|confirmation| &confirmation.ready)
    }

    /// Establish after the caller has successfully
    /// submitted the cached READY to its transport.
    ///
    /// The caller is responsible for performing the actual
    /// socket submission before invoking this method.
    pub fn into_established_after_ready_sent(
        self,
    ) -> Result<EstablishedSession, PacketProtectionError> {
        let confirmation = self
            .confirmation
            .ok_or(PacketProtectionError::ConfirmationRequired)?;

        Ok(EstablishedSession::new(self.protection, Some(confirmation)))
    }
}

impl EstablishedSession {
    fn new(protection: PacketProtection, confirmation: Option<ServerConfirmationCache>) -> Self {
        Self {
            profile: protection.profile,
            local_receive_cid: protection.local_receive_cid,
            remote_receive_cid: protection.remote_receive_cid,
            remote_endpoint: protection.remote_endpoint,
            protection: Some(protection),
            confirmation,
        }
    }

    pub fn local_receive_cid(&self) -> [u8; 8] {
        self.local_receive_cid
    }

    pub fn remote_receive_cid(&self) -> [u8; 8] {
        self.remote_receive_cid
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.remote_endpoint
    }

    /// Whether this session has been permanently closed.
    pub fn is_closed(&self) -> bool {
        self.protection.is_none()
    }

    pub fn profile(&self) -> WireProfile {
        self.profile
    }

    /// Permanently close the local session without sending a packet.
    ///
    /// The remote peer must independently detect timeout or closure.
    pub fn close_local(&mut self) {
        self.protection = None;
        self.confirmation = None;
    }

    /// Protect an unreliable application datagram.
    ///
    /// Returns the number of wire bytes written to `output`.
    /// Packet numbers are assigned internally.
    ///
    /// This operation does not perform network I/O.
    pub fn send_data(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PacketProtectionError> {
        self.send_packet(PacketType::Data, plaintext, output)
    }

    /// Generate an authenticated CLOSE and close locally.
    ///
    /// Successful generation permanently closes the session.
    /// Delivery of CLOSE to the remote peer is not guaranteed.
    pub fn send_close(&mut self, output: &mut [u8]) -> Result<usize, PacketProtectionError> {
        self.send_packet(PacketType::Close, &[], output)
    }

    fn send_packet(
        &mut self,
        kind: PacketType,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PacketProtectionError> {
        let (result, exhausted) = {
            let protection = self
                .protection
                .as_mut()
                .ok_or(PacketProtectionError::SessionClosed)?;

            let result = protection.seal(kind, plaintext, output);

            (result, protection.send_exhausted())
        };

        // A successful CLOSE or exhausted sending state
        // permanently retires the session.
        if exhausted || (kind == PacketType::Close && result.is_ok()) {
            self.close_local();
        }

        result
    }

    /// Protect a canonical congestion feedback frame.
    ///
    /// ACK is supported only by the experimental v2 profile.
    /// Every new ACK consumes a fresh directional packet number.
    pub fn send_ack(
        &mut self,
        ack: &AckFrame,
        output: &mut [u8],
    ) -> Result<usize, PacketProtectionError> {
        if self.is_closed() {
            return Err(PacketProtectionError::SessionClosed);
        }

        if !self.profile.supports_ack() {
            return Err(PacketProtectionError::UnexpectedPacket);
        }

        let plaintext = ack.encode();

        self.send_packet(PacketType::Ack, &plaintext, output)
    }

    /// Authenticate and decode one congestion feedback packet.
    ///
    /// This method does not update congestion control,
    /// sender history or application session activity.
    pub fn receive_ack(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<AckFrame, PacketProtectionError> {
        if self.is_closed() {
            return Err(PacketProtectionError::SessionClosed);
        }

        if !self.profile.supports_ack() {
            return Err(PacketProtectionError::UnexpectedPacket);
        }

        let mut plaintext = [0_u8; ACK_PLAINTEXT_LEN];

        let protection = self
            .protection
            .as_mut()
            .ok_or(PacketProtectionError::SessionClosed)?;

        let result = protection.open(source, PacketType::Ack, bytes, &mut plaintext);

        match result {
            Ok(len) => {
                AckFrame::decode(&plaintext[..len]).map_err(PacketProtectionError::InvalidAck)
            }

            Err(error) => {
                if matches!(&error, PacketProtectionError::InvalidCiphertextLength) {
                    self.close_local();
                }

                Err(error)
            }
        }
    }

    /// Authenticate and receive an application or CLOSE packet.
    ///
    /// Invalid packets do not expose plaintext or close the session.
    /// Authenticated DATA is delivered at most once.
    pub fn receive(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
        output: &mut [u8],
    ) -> Result<ReceiveEvent, PacketProtectionError> {
        let protection = self
            .protection
            .as_mut()
            .ok_or(PacketProtectionError::SessionClosed)?;

        let kind = self.profile.decode_packet(bytes)?.header.kind;

        let result = match kind {
            PacketType::Data => protection
                .open(source, PacketType::Data, bytes, output)
                .map(ReceiveEvent::Data),

            PacketType::Close => protection
                .open(source, PacketType::Close, bytes, &mut [])
                .map(|_| ReceiveEvent::Closed),

            _ => Err(PacketProtectionError::UnexpectedPacket),
        };

        if matches!(
            &result,
            Ok(ReceiveEvent::Closed) | Err(PacketProtectionError::InvalidCiphertextLength)
        ) {
            self.close_local();
        }

        result
    }

    /// Return cached READY only for an exact duplicate of the
    /// previously authenticated CONFIRM from the original endpoint.
    ///
    /// The caller must enforce deadlines and transport rate limits.
    /// This operation never performs new encryption.
    pub fn retry_ready(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Option<&[u8; crate::READY_SIZE]> {
        if self.is_closed() || source != self.remote_endpoint {
            return None;
        }

        let cache = self.confirmation.as_mut()?;

        if bytes != cache.confirm.as_slice() || cache.retries_remaining == 0 {
            return None;
        }

        cache.retries_remaining -= 1;

        Some(&cache.ready)
    }

    /// Remove handshake recovery state after its deadline.
    pub fn discard_confirmation_cache(&mut self) {
        self.confirmation = None;
    }
}

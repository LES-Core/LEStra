use std::net::SocketAddr;

use lestra_codec::PacketType;

use crate::{
    CONFIRM_SIZE, PacketProtectionError, READY_SIZE, RESPONSE_SIZE, ServerPendingConfirmation,
    VerifiedNoise, aead::PacketProtection,
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

/// Cryptographically established LEStra session.
///
/// Application DATA and CLOSE APIs are not implemented yet.
pub struct EstablishedSession {
    protection: PacketProtection,
    confirmation: Option<ServerConfirmationCache>,
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

        Ok(EstablishedSession {
            protection: self.protection,
            confirmation: None,
        })
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
        let confirmation = self
            .confirmation
            .ok_or(PacketProtectionError::ConfirmationRequired)?;

        let ready = confirmation.ready;

        Ok((
            EstablishedSession {
                protection: self.protection,
                confirmation: Some(confirmation),
            },
            ready,
        ))
    }
}

impl EstablishedSession {
    pub fn local_receive_cid(&self) -> [u8; 8] {
        self.protection.local_receive_cid
    }

    pub fn remote_receive_cid(&self) -> [u8; 8] {
        self.protection.remote_receive_cid
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.protection.remote_endpoint
    }

    /// Return cached READY only for an exact duplicate of the
    /// previously authenticated CONFIRM from the original endpoint.
    ///
    /// The caller must enforce deadlines and transport rate limits.
    /// This operation never performs new encryption.
    pub fn retry_ready(&mut self, source: SocketAddr, bytes: &[u8]) -> Option<&[u8; READY_SIZE]> {
        if source != self.protection.remote_endpoint {
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

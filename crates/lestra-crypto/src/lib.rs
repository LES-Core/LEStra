//! Experimental Noise IK handshake for LEStra native UDP.
//!
//! Completes the two Noise IK messages and verifies peer identity, endpoint,
//! CIDs and authenticated header echoes. This crate **does not** implement
//! CONFIRM/READY, protected DATA, replay handling, retransmissions or key
//! export. A completed Noise handshake is NOT an established LEStra session.
//!
//! We intentionally DO NOT enable snow's "risky-raw-split" feature or use its
//! transport convenience methods: those do not provide LEStra's mandatory
//! full-header AEAD associated data contract.
//!
//! A higher layer must perform cheap parsing, rate limiting, ACL lookup,
//! bounded pending-session admission, source binding and 3:1 accounting.

use core::fmt;
use std::net::SocketAddr;

use lestra_codec::{
    CodecError, PacketHeader, PacketType, decode_packet, encode_header, encode_packet_into,
};
use snow::{Builder, HandshakeState, params::NoiseParams};

const PROLOGUE: &[u8] = b"LEStra/native-udp/v1";
const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
pub const INITIAL_SIZE: usize = 156;
pub const RESPONSE_SIZE: usize = 108;
const INITIAL_BODY_SIZE: usize = 130;
const RESPONSE_BODY_SIZE: usize = 82;
const ECHO_SIZE: usize = 34;

#[derive(Debug)]
pub enum HandshakeError {
    Codec(CodecError),
    Noise(snow::Error),
    InvalidConnectionId,
    UnexpectedPeer,
    UnexpectedPacket,
    InvalidHandshakePayload,
    HeaderEchoMismatch,
    UnauthorizedClient,
    IncompleteNoiseHandshake,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(err) => write!(f, "invalid LEStra packet: {err}"),
            Self::Noise(_) => f.write_str("Noise authentication failed"),
            Self::InvalidConnectionId => f.write_str("invalid receive CID"),
            Self::UnexpectedPeer => f.write_str("packet arrived from another endpoint"),
            Self::UnexpectedPacket => f.write_str("unexpected handshake packet"),
            Self::InvalidHandshakePayload => f.write_str("invalid decrypted Noise payload"),
            Self::HeaderEchoMismatch => f.write_str("Noise payload/header binding mismatch"),
            Self::UnauthorizedClient => f.write_str("client identity is not authorized"),
            Self::IncompleteNoiseHandshake => f.write_str("Noise IK handshake incomplete"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<CodecError> for HandshakeError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}
impl From<snow::Error> for HandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

fn params() -> NoiseParams {
    PATTERN.parse().expect("constant Noise IK suite must be valid")
}

fn valid_cid(cid: [u8; 8]) -> Result<(), HandshakeError> {
    if cid == [0_u8; 8] {
        return Err(HandshakeError::InvalidConnectionId);
    }
    Ok(())
}

/// Client before it emits INITIAL. The caller must provision authenticated,
/// non-test static keys and generate a fresh unpredictable receive CID.
pub struct ClientStart {
    noise: HandshakeState,
    client_receive_cid: [u8; 8],
    expected_server_endpoint: SocketAddr,
}

/// Awaiting the encrypted Noise HANDSHAKE. The INITIAL bytes are immutable and
/// can be resent by a bounded retry controller with NO new Noise encryption.
pub struct ClientPending {
    noise: HandshakeState,
    client_receive_cid: [u8; 8],
    expected_server_endpoint: SocketAddr,
    initial: [u8; INITIAL_SIZE],
}

/// Server with its own key and an explicitly approved client static key.
/// The transport must apply admission limits BEFORE constructing this object.
pub struct ServerStart {
    noise: HandshakeState,
    allowed_client_static: [u8; 32],
    server_receive_cid: [u8; 8],
}

/// A verified Noise IK transcript, **not** an established LEStra session.
/// The Snow state is deliberately private: exposing a raw Split key or a
/// transport mode without explicit AAD would violate the v1 candidate spec.
pub struct VerifiedNoise {
    noise: HandshakeState,
    local_receive_cid: [u8; 8],
    remote_receive_cid: [u8; 8],
    remote_endpoint: SocketAddr,
}

impl VerifiedNoise {
    pub fn local_receive_cid(&self) -> [u8; 8] {
        self.local_receive_cid
    }

    pub fn remote_receive_cid(&self) -> [u8; 8] {
        self.remote_receive_cid
    }

    pub fn remote_endpoint(&self) -> SocketAddr {
        self.remote_endpoint
    }

    pub fn transcript_hash(&self) -> &[u8] {
        self.noise.get_handshake_hash()
    }

    pub fn noise_complete(&self) -> bool {
        self.noise.is_handshake_finished()
    }
}

/// Server's completed Noise message and the *cached* response to retransmit.
/// CONFIRM has not been received; do not deliver application DATA.
pub struct ServerPendingConfirmation {
    verified: VerifiedNoise,
    response: [u8; RESPONSE_SIZE],
}

impl ServerPendingConfirmation {
    pub fn response(&self) -> &[u8; RESPONSE_SIZE] {
        &self.response
    }

    pub fn verified_noise(&self) -> &VerifiedNoise {
        &self.verified
    }
}

impl ClientStart {
    pub fn new(
        client_static_private: &[u8; 32],
        pinned_server_static: &[u8; 32],
        client_receive_cid: [u8; 8],
        expected_server_endpoint: SocketAddr,
    ) -> Result<Self, HandshakeError> {
        valid_cid(client_receive_cid)?;
        let noise = Builder::new(params())
            .local_private_key(client_static_private)?
            .remote_public_key(pinned_server_static)?
            .prologue(PROLOGUE)?
            .build_initiator()?;
        Ok(Self {
            noise,
            client_receive_cid,
            expected_server_endpoint,
        })
    }

    /// First Noise IK flight. Consumes Self to prohibit accidental nonce reuse.
    pub fn start(mut self) -> Result<ClientPending, HandshakeError> {
        let header = PacketHeader {
            kind: PacketType::Initial,
            destination_connection_id: [0; 8],
            packet_number: 0,
        };
        let mut raw_header = [0_u8; 26];
        encode_header(header, INITIAL_BODY_SIZE, &mut raw_header)?;
        let mut plaintext = [0_u8; ECHO_SIZE];
        plaintext[..26].copy_from_slice(&raw_header);
        plaintext[26..].copy_from_slice(&self.client_receive_cid);

        let mut message = [0_u8; INITIAL_BODY_SIZE];
        let written = self.noise.write_message(&plaintext, &mut message)?;
        if written != INITIAL_BODY_SIZE {
            return Err(HandshakeError::InvalidHandshakePayload);
        }
        let mut initial = [0_u8; INITIAL_SIZE];
        let _ = encode_packet_into(header, &message, &mut initial)?;
        Ok(ClientPending {
            noise: self.noise,
            client_receive_cid: self.client_receive_cid,
            expected_server_endpoint: self.expected_server_endpoint,
            initial,
        })
    }
}

impl ClientPending {
    pub fn initial(&self) -> &[u8; INITIAL_SIZE] {
        &self.initial
    }

    /// Consumes this attempt. Invalid incoming data fails closed; the caller
    /// can initiate a fresh Noise attempt, not resume with an old nonce.
    pub fn accept_response(
        mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<VerifiedNoise, HandshakeError> {
        if source != self.expected_server_endpoint {
            return Err(HandshakeError::UnexpectedPeer);
        }
        let packet = decode_packet(bytes)?;
        if packet.header.kind != PacketType::Handshake
            || packet.header.destination_connection_id != self.client_receive_cid
        {
            return Err(HandshakeError::UnexpectedPacket);
        }
        let mut plaintext = [0_u8; ECHO_SIZE];
        let written = self.noise.read_message(packet.body, &mut plaintext)?;
        if written != ECHO_SIZE {
            return Err(HandshakeError::InvalidHandshakePayload);
        }
        if &plaintext[..26] != packet.raw_header {
            return Err(HandshakeError::HeaderEchoMismatch);
        }
        let server_receive_cid: [u8; 8] = plaintext[26..]
            .try_into()
            .expect("34-byte Noise echo was fully checked");
        valid_cid(server_receive_cid)?;
        if !self.noise.is_handshake_finished() {
            return Err(HandshakeError::IncompleteNoiseHandshake);
        }
        Ok(VerifiedNoise {
            noise: self.noise,
            local_receive_cid: self.client_receive_cid,
            remote_receive_cid: server_receive_cid,
            remote_endpoint: source,
        })
    }
}

impl ServerStart {
    pub fn new(
        server_static_private: &[u8; 32],
        allowed_client_static: [u8; 32],
        server_receive_cid: [u8; 8],
    ) -> Result<Self, HandshakeError> {
        valid_cid(server_receive_cid)?;
        let noise = Builder::new(params())
            .local_private_key(server_static_private)?
            .prologue(PROLOGUE)?
            .build_responder()?;
        Ok(Self {
            noise,
            allowed_client_static,
            server_receive_cid,
        })
    }

    /// Validate and authenticate INITIAL, then emit a single cached HANDSHAKE.
    /// Caller must reserve the remote source's amplification budget before
    /// actually transmitting the returned 108-byte packet.
    pub fn accept_initial(
        mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<ServerPendingConfirmation, HandshakeError> {
        let packet = decode_packet(bytes)?;
        if packet.header.kind != PacketType::Initial {
            return Err(HandshakeError::UnexpectedPacket);
        }
        let mut plaintext = [0_u8; ECHO_SIZE];
        let written = self.noise.read_message(packet.body, &mut plaintext)?;
        if written != ECHO_SIZE {
            return Err(HandshakeError::InvalidHandshakePayload);
        }
        if &plaintext[..26] != packet.raw_header {
            return Err(HandshakeError::HeaderEchoMismatch);
        }
        let client_receive_cid: [u8; 8] = plaintext[26..]
            .try_into()
            .expect("34-byte Noise echo was fully checked");
        valid_cid(client_receive_cid)?;

        // The public identity is authenticated by Noise's successful IK
        // DecryptAndHash. Authorization is a separate policy decision.
        if self.noise.get_remote_static() != Some(self.allowed_client_static.as_slice()) {
            return Err(HandshakeError::UnauthorizedClient);
        }

        let header = PacketHeader {
            kind: PacketType::Handshake,
            destination_connection_id: client_receive_cid,
            packet_number: 0,
        };
        let mut raw_header = [0_u8; 26];
        encode_header(header, RESPONSE_BODY_SIZE, &mut raw_header)?;
        let mut response_plaintext = [0_u8; ECHO_SIZE];
        response_plaintext[..26].copy_from_slice(&raw_header);
        response_plaintext[26..].copy_from_slice(&self.server_receive_cid);

        let mut message = [0_u8; RESPONSE_BODY_SIZE];
        let written = self.noise.write_message(&response_plaintext, &mut message)?;
        if written != RESPONSE_BODY_SIZE || !self.noise.is_handshake_finished() {
            return Err(HandshakeError::IncompleteNoiseHandshake);
        }
        let mut response = [0_u8; RESPONSE_SIZE];
        let _ = encode_packet_into(header, &message, &mut response)?;

        Ok(ServerPendingConfirmation {
            response,
            verified: VerifiedNoise {
                noise: self.noise,
                local_receive_cid: self.server_receive_cid,
                remote_receive_cid: client_receive_cid,
                remote_endpoint: source,
            },
        })
    }
}

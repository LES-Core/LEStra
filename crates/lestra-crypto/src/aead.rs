use core::fmt;
use std::net::SocketAddr;

use lestra_codec::{
    AEAD_TAG_LEN, CodecError, HEADER_LEN, MAX_DATAGRAM_LEN, MAX_PACKET_NUMBER_EXCLUSIVE,
    PacketHeader, PacketType, encode_header,
};
use snow::StatelessTransportState;

use super::VerifiedNoise;

const MAX_PLAINTEXT_LEN: usize = MAX_DATAGRAM_LEN - HEADER_LEN - AEAD_TAG_LEN;

#[derive(Debug)]
pub enum PacketProtectionError {
    Codec(CodecError),
    Noise(snow::Error),
    CounterExhausted,
    UnexpectedPacket,
    InvalidCiphertextLength,
}

impl fmt::Display for PacketProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(err) => write!(f, "invalid packet: {err}"),
            Self::Noise(_) => f.write_str("packet protection failed"),
            Self::CounterExhausted => f.write_str("send state exhausted; reconnect required"),
            Self::UnexpectedPacket => f.write_str("unexpected protected packet type"),
            Self::InvalidCiphertextLength => f.write_str("unexpected ciphertext length"),
        }
    }
}

impl std::error::Error for PacketProtectionError {}

impl From<CodecError> for PacketProtectionError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<snow::Error> for PacketProtectionError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

/// Internal packet protection state.
///
/// Owns the directional Noise cipher states and the transmit counter.
/// Must never be cloned, reset or restored after a process restart.
pub(super) struct PacketProtection {
    noise: StatelessTransportState,
    next_send: u64,

    pub(super) local_receive_cid: [u8; 8],
    pub(super) remote_receive_cid: [u8; 8],
    pub(super) remote_endpoint: SocketAddr,
}

impl PacketProtection {
    pub(super) fn from_verified(verified: VerifiedNoise) -> Result<Self, PacketProtectionError> {
        Ok(Self {
            noise: verified.noise.into_stateless_transport_mode()?,
            next_send: 0,
            local_receive_cid: verified.local_receive_cid,
            remote_receive_cid: verified.remote_receive_cid,
            remote_endpoint: verified.remote_endpoint,
        })
    }

    /// Encrypt a new protected packet with its complete wire header.
    ///
    /// Packet numbers are assigned internally. Retransmissions must
    /// reuse cached packet bytes instead of calling this method again.
    ///
    /// The caller must enforce the handshake and session lifecycle.
    pub(super) fn seal(
        &mut self,
        kind: PacketType,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PacketProtectionError> {
        if self.next_send >= MAX_PACKET_NUMBER_EXCLUSIVE {
            return Err(PacketProtectionError::CounterExhausted);
        }

        let allowed = if self.next_send == 0 {
            if self.noise.is_initiator() {
                kind == PacketType::Confirm
            } else {
                kind == PacketType::Ready
            }
        } else {
            matches!(kind, PacketType::Data | PacketType::Close)
        };

        if !allowed {
            return Err(PacketProtectionError::UnexpectedPacket);
        }

        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CodecError::Oversized.into());
        }

        let packet_number = self.next_send;
        let body_len = plaintext.len() + AEAD_TAG_LEN;
        let required = HEADER_LEN + body_len;

        let header = PacketHeader {
            kind,
            destination_connection_id: self.remote_receive_cid,
            packet_number,
        };

        let mut raw_header = [0_u8; HEADER_LEN];
        encode_header(header, body_len, &mut raw_header)?;

        if output.len() < required {
            return Err(CodecError::OutputTooSmall {
                required,
                available: output.len(),
            }
            .into());
        }

        // Reserve the nonce before invoking the cipher.
        // Never roll this counter back.
        self.next_send += 1;

        let written = match self.noise.write_message_with_additional_data(
            packet_number,
            &raw_header,
            plaintext,
            &mut output[HEADER_LEN..required],
        ) {
            Ok(written) => written,
            Err(error) => {
                // Invalidate the sending state on cipher failure.
                self.next_send = MAX_PACKET_NUMBER_EXCLUSIVE;
                return Err(error.into());
            }
        };

        if written != body_len {
            self.next_send = MAX_PACKET_NUMBER_EXCLUSIVE;
            return Err(PacketProtectionError::InvalidCiphertextLength);
        }

        output[..HEADER_LEN].copy_from_slice(&raw_header);

        Ok(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CONFIRM_SIZE, ClientStart, ServerStart};
    use lestra_codec::decode_packet;
    use snow::{Builder, params::NoiseParams};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn verified_pair() -> Result<(VerifiedNoise, VerifiedNoise), Box<dyn std::error::Error>> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

        let builder = Builder::new(params);

        let client_key = builder.generate_keypair()?;
        let server_key = builder.generate_keypair()?;

        let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;
        let client_public: [u8; 32] = client_key.public.as_slice().try_into()?;
        let server_private: [u8; 32] = server_key.private.as_slice().try_into()?;
        let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

        let client_addr = SocketAddr::from(([127, 0, 0, 1], 4000));
        let server_addr = SocketAddr::from(([127, 0, 0, 1], 5000));

        let client =
            ClientStart::new(&client_private, &server_public, [1; 8], server_addr)?.start()?;

        let server = ServerStart::new(&server_private, client_public, [2; 8])?
            .accept_initial(client_addr, client.initial())?;

        let client = client.accept_response(server_addr, server.response())?;

        Ok((client, server.verified))
    }

    #[test]
    fn client_confirmation_is_authenticated_and_cached() -> TestResult {
        let (client, server) = verified_pair()?;

        let client = client.start_confirmation()?;
        let packet = decode_packet(client.confirm())?;

        assert_eq!(client.confirm().len(), CONFIRM_SIZE);
        assert_eq!(packet.header.kind, PacketType::Confirm);
        assert_eq!(packet.header.packet_number, 0);
        assert_eq!(packet.header.destination_connection_id, [2; 8]);
        assert_eq!(packet.body.len(), AEAD_TAG_LEN);

        let receiver = server.noise.into_stateless_transport_mode()?;

        let mut plaintext = [0_u8; 1];

        let written = receiver.read_message_with_additional_data(
            0,
            packet.raw_header,
            packet.body,
            &mut plaintext,
        )?;

        assert_eq!(written, 0);

        let mut tampered_header = *packet.raw_header;
        tampered_header[8] ^= 1;

        assert!(
            receiver
                .read_message_with_additional_data(0, &tampered_header, packet.body, &mut plaintext,)
                .is_err()
        );

        let cached = *client.confirm();

        assert_eq!(client.confirm(), &cached);

        Ok(())
    }

    #[test]
    fn packet_numbers_increase_without_reuse() -> TestResult {
        let (client, _) = verified_pair()?;
        let mut protection = PacketProtection::from_verified(client)?;

        let mut output = [0_u8; MAX_DATAGRAM_LEN];

        let len = protection.seal(PacketType::Confirm, &[], &mut output)?;

        assert_eq!(decode_packet(&output[..len])?.header.packet_number, 0);

        assert!(matches!(
            protection.seal(PacketType::Confirm, &[], &mut output),
            Err(PacketProtectionError::UnexpectedPacket)
        ));

        for expected in 1..=4 {
            let len = protection.seal(PacketType::Data, b"LEStra", &mut output)?;

            let packet = decode_packet(&output[..len])?;
            assert_eq!(packet.header.packet_number, expected);
        }

        assert_eq!(protection.next_send, 5);

        Ok(())
    }

    #[test]
    fn invalid_input_does_not_consume_nonce() -> TestResult {
        let (client, _) = verified_pair()?;
        let mut protection = PacketProtection::from_verified(client)?;

        let mut small = [0_u8; CONFIRM_SIZE - 1];

        assert!(matches!(
            protection.seal(PacketType::Confirm, &[], &mut small),
            Err(PacketProtectionError::Codec(
                CodecError::OutputTooSmall { .. }
            ))
        ));

        assert_eq!(protection.next_send, 0);

        let mut output = [0_u8; MAX_DATAGRAM_LEN];

        assert!(matches!(
            protection.seal(PacketType::Data, b"early", &mut output),
            Err(PacketProtectionError::UnexpectedPacket)
        ));

        assert_eq!(protection.next_send, 0);

        protection.seal(PacketType::Confirm, &[], &mut output)?;

        let oversized = [0_u8; MAX_PLAINTEXT_LEN + 1];

        assert!(matches!(
            protection.seal(PacketType::Data, &oversized, &mut output),
            Err(PacketProtectionError::Codec(CodecError::Oversized))
        ));

        assert_eq!(protection.next_send, 1);

        Ok(())
    }

    #[test]
    fn sender_rejects_counter_exhaustion() -> TestResult {
        let (client, _) = verified_pair()?;
        let mut protection = PacketProtection::from_verified(client)?;

        let mut output = [0_u8; MAX_DATAGRAM_LEN];

        protection.seal(PacketType::Confirm, &[], &mut output)?;

        // Test-only jump to the protocol's final permitted nonce.
        protection.next_send = MAX_PACKET_NUMBER_EXCLUSIVE - 1;

        let len = protection.seal(PacketType::Data, b"last packet", &mut output)?;

        assert_eq!(
            decode_packet(&output[..len])?.header.packet_number,
            MAX_PACKET_NUMBER_EXCLUSIVE - 1
        );

        assert!(matches!(
            protection.seal(PacketType::Data, b"overflow", &mut output),
            Err(PacketProtectionError::CounterExhausted)
        ));

        assert_eq!(protection.next_send, MAX_PACKET_NUMBER_EXCLUSIVE);

        Ok(())
    }

    #[test]
    fn first_packet_depends_on_noise_role() -> TestResult {
        let (client, server) = verified_pair()?;

        let mut client = PacketProtection::from_verified(client)?;
        let mut server = PacketProtection::from_verified(server)?;

        let mut output = [0_u8; MAX_DATAGRAM_LEN];

        assert!(matches!(
            client.seal(PacketType::Ready, &[], &mut output),
            Err(PacketProtectionError::UnexpectedPacket)
        ));

        assert!(matches!(
            server.seal(PacketType::Confirm, &[], &mut output),
            Err(PacketProtectionError::UnexpectedPacket)
        ));

        assert_eq!(client.next_send, 0);
        assert_eq!(server.next_send, 0);

        let len = server.seal(PacketType::Ready, &[], &mut output)?;
        let packet = decode_packet(&output[..len])?;

        assert_eq!(packet.header.kind, PacketType::Ready);
        assert_eq!(packet.header.packet_number, 0);

        Ok(())
    }

    #[test]
    fn maximum_datagram_size_is_supported() -> TestResult {
        let (client, _) = verified_pair()?;
        let mut protection = PacketProtection::from_verified(client)?;

        let mut output = [0_u8; MAX_DATAGRAM_LEN];

        protection.seal(PacketType::Confirm, &[], &mut output)?;

        let plaintext = [42_u8; MAX_PLAINTEXT_LEN];

        let len = protection.seal(PacketType::Data, &plaintext, &mut output)?;

        assert_eq!(len, MAX_DATAGRAM_LEN);

        let packet = decode_packet(&output[..len])?;

        assert_eq!(packet.body.len(), MAX_PLAINTEXT_LEN + AEAD_TAG_LEN);

        Ok(())
    }
}

//! Experimental native UDP wire profile with ACK support.
//!
//! This module validates framing only.
//! It does not authenticate packets or negotiate profiles.

mod ack;

pub use ack::{
    ACK_BITMAP_BITS, ACK_BITMAP_LEN, ACK_BODY_LEN, ACK_PACKET_LEN, ACK_PLAINTEXT_LEN, AckError,
    AckFrame,
};

use crate::{CodecError, HEADER_LEN, MAX_DATAGRAM_LEN, MAX_PACKET_NUMBER_EXCLUSIVE};

pub const DRAFT_WIRE_MAJOR: u8 = 2;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Initial = 1,
    Handshake = 2,
    Confirm = 3,
    Data = 4,
    Close = 5,
    Ready = 6,
    Ack = 7,
}

impl TryFrom<u8> for PacketType {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initial),
            2 => Ok(Self::Handshake),
            3 => Ok(Self::Confirm),
            4 => Ok(Self::Data),
            5 => Ok(Self::Close),
            6 => Ok(Self::Ready),
            7 => Ok(Self::Ack),

            other => Err(CodecError::InvalidType(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub kind: PacketType,
    pub destination_connection_id: [u8; 8],
    pub packet_number: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedPacket<'a> {
    pub header: PacketHeader,
    pub raw_header: &'a [u8; HEADER_LEN],
    pub body: &'a [u8],
}

fn validate(header: PacketHeader, body_len: usize) -> Result<(), CodecError> {
    if body_len > MAX_DATAGRAM_LEN - HEADER_LEN {
        return Err(CodecError::Oversized);
    }

    if header.kind == PacketType::Ack {
        if header.destination_connection_id == [0; 8] {
            return Err(CodecError::InvalidConnectionId);
        }

        if header.packet_number == 0 || header.packet_number >= MAX_PACKET_NUMBER_EXCLUSIVE {
            return Err(CodecError::InvalidPacketNumber);
        }

        if body_len != ACK_BODY_LEN {
            return Err(CodecError::InvalidBodyLength);
        }

        return Ok(());
    }

    // Existing packet types retain their structural rules.
    let legacy_kind = crate::PacketType::try_from(header.kind as u8)?;

    crate::validate(
        crate::PacketHeader {
            kind: legacy_kind,
            destination_connection_id: header.destination_connection_id,
            packet_number: header.packet_number,
        },
        body_len,
    )
}

/// Decode exactly one experimental v2 datagram.
///
/// The returned body is opaque and unauthenticated.
pub fn decode_packet(bytes: &[u8]) -> Result<DecodedPacket<'_>, CodecError> {
    if bytes.len() < HEADER_LEN {
        return Err(CodecError::Truncated);
    }

    if bytes.len() > MAX_DATAGRAM_LEN {
        return Err(CodecError::Oversized);
    }

    if &bytes[..4] != b"LSTR" {
        return Err(CodecError::InvalidMagic);
    }

    if bytes[4] != DRAFT_WIRE_MAJOR {
        return Err(CodecError::UnsupportedVersion(bytes[4]));
    }

    let kind = PacketType::try_from(bytes[5])?;

    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(CodecError::ReservedFlags);
    }

    let body_len = usize::from(u16::from_be_bytes([bytes[24], bytes[25]]));

    if body_len != bytes.len() - HEADER_LEN {
        return Err(CodecError::LengthMismatch);
    }

    let header = PacketHeader {
        kind,

        destination_connection_id: bytes[8..16].try_into().expect("header length checked"),

        packet_number: u64::from_be_bytes(bytes[16..24].try_into().expect("header length checked")),
    };

    validate(header, body_len)?;

    let raw_header = bytes[..HEADER_LEN]
        .try_into()
        .expect("header length checked");

    Ok(DecodedPacket {
        header,
        raw_header,
        body: &bytes[HEADER_LEN..],
    })
}

/// Encode a canonical v2 header.
///
/// The exact resulting bytes must be authenticated
/// as header echo or AEAD associated data.
pub fn encode_header(
    header: PacketHeader,
    body_len: usize,
    output: &mut [u8; HEADER_LEN],
) -> Result<(), CodecError> {
    validate(header, body_len)?;

    output[..4].copy_from_slice(b"LSTR");
    output[4] = DRAFT_WIRE_MAJOR;
    output[5] = header.kind as u8;

    output[6..8].fill(0);

    output[8..16].copy_from_slice(&header.destination_connection_id);

    output[16..24].copy_from_slice(&header.packet_number.to_be_bytes());

    let body_len: u16 = body_len.try_into().expect("body length validated");

    output[24..26].copy_from_slice(&body_len.to_be_bytes());

    Ok(())
}

/// Encode an already prepared Noise or AEAD body.
///
/// Validation errors leave the output unchanged.
pub fn encode_packet_into<'a>(
    header: PacketHeader,
    body: &[u8],
    output: &'a mut [u8],
) -> Result<&'a [u8], CodecError> {
    let mut raw_header = [0_u8; HEADER_LEN];

    encode_header(header, body.len(), &mut raw_header)?;

    let required = HEADER_LEN + body.len();

    if output.len() < required {
        return Err(CodecError::OutputTooSmall {
            required,
            available: output.len(),
        });
    }

    output[..HEADER_LEN].copy_from_slice(&raw_header);

    output[HEADER_LEN..required].copy_from_slice(body);

    Ok(&output[..required])
}

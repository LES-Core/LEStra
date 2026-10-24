//! Allocation-free framing for the candidate LEStra native UDP wire format.
//!
//! This codec checks syntax only. The caller MUST authenticate the handshake
//! and encrypted packet, check the peer/source CID, session state, replay, and
//! authorization. A successful decode does not imply valid plaintext.
//!
//! Draft major 1 is NOT a declaration that the production protocol is stable.

use core::fmt;

pub const HEADER_LEN: usize = 26;
pub const MAX_DATAGRAM_LEN: usize = 1200;
pub const AEAD_TAG_LEN: usize = 16;
pub const DRAFT_WIRE_MAJOR: u8 = 1;
pub const MAX_PACKET_NUMBER_EXCLUSIVE: u64 = 1_u64 << 32;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Initial = 1,
    Handshake = 2,
    Confirm = 3,
    Data = 4,
    Close = 5,
    Ready = 6,
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
            other => Err(CodecError::InvalidType(other)),
        }
    }
}

/// Public metadata only; a connection ID is not authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub kind: PacketType,
    pub destination_connection_id: [u8; 8],
    pub packet_number: u64,
}

/// Borrowed view of the original packet, with no copying or heap allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedPacket<'a> {
    pub header: PacketHeader,
    /// Raw wire bytes to authenticate as AEAD associated data or Noise echo.
    pub raw_header: &'a [u8; HEADER_LEN],
    /// Opaque bytes. For protected packets, includes ciphertext and AEAD tag.
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    Truncated,
    Oversized,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidType(u8),
    ReservedFlags,
    LengthMismatch,
    InvalidConnectionId,
    InvalidPacketNumber,
    InvalidBodyLength,
    OutputTooSmall { required: usize, available: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated LEStra header"),
            Self::Oversized => f.write_str("oversized LEStra datagram"),
            Self::InvalidMagic => f.write_str("invalid LEStra packet magic"),
            Self::UnsupportedVersion(_) => f.write_str("unsupported LEStra draft version"),
            Self::InvalidType(_) => f.write_str("invalid LEStra packet type"),
            Self::ReservedFlags => f.write_str("nonzero reserved flags"),
            Self::LengthMismatch => f.write_str("body length does not match datagram"),
            Self::InvalidConnectionId => f.write_str("invalid connection ID"),
            Self::InvalidPacketNumber => f.write_str("invalid packet number"),
            Self::InvalidBodyLength => f.write_str("invalid packet body size"),
            Self::OutputTooSmall { .. } => f.write_str("insufficient output space"),
        }
    }
}

impl std::error::Error for CodecError {}

fn validate(header: PacketHeader, body_len: usize) -> Result<(), CodecError> {
    if body_len > MAX_DATAGRAM_LEN - HEADER_LEN {
        return Err(CodecError::Oversized);
    }

    let zero_cid = header.destination_connection_id == [0; 8];
    match header.kind {
        PacketType::Initial => {
            if !zero_cid {
                return Err(CodecError::InvalidConnectionId);
            }
            if header.packet_number != 0 {
                return Err(CodecError::InvalidPacketNumber);
            }
            if body_len != 130 {
                return Err(CodecError::InvalidBodyLength);
            }
        }
        PacketType::Handshake => {
            if zero_cid {
                return Err(CodecError::InvalidConnectionId);
            }
            if header.packet_number != 0 {
                return Err(CodecError::InvalidPacketNumber);
            }
            if body_len != 82 {
                return Err(CodecError::InvalidBodyLength);
            }
        }
        PacketType::Confirm | PacketType::Ready => {
            if zero_cid {
                return Err(CodecError::InvalidConnectionId);
            }
            if header.packet_number != 0 {
                return Err(CodecError::InvalidPacketNumber);
            }
            if body_len != AEAD_TAG_LEN {
                return Err(CodecError::InvalidBodyLength);
            }
        }
        PacketType::Data | PacketType::Close => {
            if zero_cid {
                return Err(CodecError::InvalidConnectionId);
            }
            if header.packet_number == 0
                || header.packet_number >= MAX_PACKET_NUMBER_EXCLUSIVE
            {
                return Err(CodecError::InvalidPacketNumber);
            }
            if (header.kind == PacketType::Data && body_len < AEAD_TAG_LEN)
                || (header.kind == PacketType::Close && body_len != AEAD_TAG_LEN)
            {
                return Err(CodecError::InvalidBodyLength);
            }
        }
    }
    Ok(())
}

/// Validate and borrow exactly one complete native UDP envelope.
///
/// The returned body is NOT authenticated or decrypted. Crypto/session code
/// must authenticate the exact raw header and ciphertext before delivery.
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
    let cid: [u8; 8] = bytes[8..16].try_into().expect("26-byte header checked");
    let packet_number = u64::from_be_bytes(
        bytes[16..24].try_into().expect("26-byte header checked"),
    );
    let header = PacketHeader {
        kind,
        destination_connection_id: cid,
        packet_number,
    };
    validate(header, body_len)?;
    let raw_header = bytes[..HEADER_LEN]
        .try_into()
        .expect("26-byte header checked");
    Ok(DecodedPacket {
        header,
        raw_header,
        body: &bytes[HEADER_LEN..],
    })
}

/// Write a canonical header into the caller's 26-byte buffer.
///
/// Use these exact header bytes as Noise header echo or AEAD associated data.
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
    let len: u16 = body_len.try_into().expect("maximum body is 1174 bytes");
    output[24..26].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// Encode a complete framed datagram into caller-provided memory.
///
/// Body is the *already prepared* Noise message or ciphertext+tag. No encryption
/// is performed. Validation errors leave output completely unchanged.
pub fn encode_packet_into<'a>(
    header: PacketHeader,
    body: &[u8],
    output: &'a mut [u8],
) -> Result<&'a [u8], CodecError> {
    validate(header, body.len())?;
    let required = HEADER_LEN + body.len();
    if output.len() < required {
        return Err(CodecError::OutputTooSmall {
            required,
            available: output.len(),
        });
    }
    let mut raw_header = [0; HEADER_LEN];
    encode_header(header, body.len(), &mut raw_header)?;
    output[..HEADER_LEN].copy_from_slice(&raw_header);
    output[HEADER_LEN..required].copy_from_slice(body);
    Ok(&output[..required])
}

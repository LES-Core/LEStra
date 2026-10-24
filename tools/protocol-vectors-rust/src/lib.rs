//! Test-only LEStra v1 framing oracle. Not a production codec or authentication layer.
pub const HEADER_LEN: usize = 26;
pub const MAX_UDP_PAYLOAD: usize = 1200;
pub const MAX_PACKET_NUMBER_EXCLUSIVE: u64 = 1 << 32;
pub const AEAD_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated, Oversized, InvalidMagic, UnsupportedVersion,
    InvalidType, ReservedFlags, LengthMismatch, InvalidConnectionId,
    InvalidPacketNumber, InvalidBodyLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub kind: u8,
    pub dcid: [u8; 8],
    pub packet_number: u64,
    pub header: &'a [u8],
    pub body: &'a [u8],
}

/// Performs only bounded syntactic checks, with borrowed slices and no allocation.
/// Ciphertext remains unauthenticated until the Noise/AEAD layer verifies it.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope<'_>, DecodeError> {
    if bytes.len() < HEADER_LEN { return Err(DecodeError::Truncated); }
    if bytes.len() > MAX_UDP_PAYLOAD { return Err(DecodeError::Oversized); }
    if &bytes[..4] != b"LSTR" { return Err(DecodeError::InvalidMagic); }
    if bytes[4] != 1 { return Err(DecodeError::UnsupportedVersion); }
    let kind = bytes[5];
    if !(1..=6).contains(&kind) { return Err(DecodeError::InvalidType); }
    if bytes[6] != 0 || bytes[7] != 0 { return Err(DecodeError::ReservedFlags); }
    let body_len = usize::from(u16::from_be_bytes([bytes[24], bytes[25]]));
    if body_len != bytes.len() - HEADER_LEN { return Err(DecodeError::LengthMismatch); }
    let dcid: [u8; 8] = bytes[8..16].try_into().expect("26-byte header validated");
    let packet_number = u64::from_be_bytes(bytes[16..24].try_into().expect("26-byte header validated"));
    let empty_cid = dcid == [0; 8];

    match kind {
        1 => {
            if !empty_cid { return Err(DecodeError::InvalidConnectionId); }
            if packet_number != 0 { return Err(DecodeError::InvalidPacketNumber); }
            if body_len != 130 { return Err(DecodeError::InvalidBodyLength); }
        }
        2 => {
            if empty_cid { return Err(DecodeError::InvalidConnectionId); }
            if packet_number != 0 { return Err(DecodeError::InvalidPacketNumber); }
            if body_len != 82 { return Err(DecodeError::InvalidBodyLength); }
        }
        3..=6 => {
            if empty_cid { return Err(DecodeError::InvalidConnectionId); }
            if packet_number >= MAX_PACKET_NUMBER_EXCLUSIVE {
                return Err(DecodeError::InvalidPacketNumber);
            }
            if (kind == 4 && body_len < AEAD_TAG_LEN)
                || (kind != 4 && body_len != AEAD_TAG_LEN) {
                return Err(DecodeError::InvalidBodyLength);
            }
        }
        _ => return Err(DecodeError::InvalidType),
    }

    Ok(Envelope {
        kind, dcid, packet_number,
        header: &bytes[..HEADER_LEN],
        body: &bytes[HEADER_LEN..],
    })
}

use core::fmt;

use crate::{AEAD_TAG_LEN, HEADER_LEN, MAX_PACKET_NUMBER_EXCLUSIVE};

pub const ACK_BITMAP_BITS: usize = 1024;
pub const ACK_BITMAP_LEN: usize = ACK_BITMAP_BITS / 8;

pub const ACK_PLAINTEXT_LEN: usize = 8 + ACK_BITMAP_LEN;
pub const ACK_BODY_LEN: usize = ACK_PLAINTEXT_LEN + AEAD_TAG_LEN;
pub const ACK_PACKET_LEN: usize = HEADER_LEN + ACK_BODY_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckError {
    InvalidLength,
    InvalidLargest,
    MissingLargest,
    InvalidBitmap,
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid ACK plaintext length"),

            Self::InvalidLargest => f.write_str("invalid largest acknowledged packet number"),

            Self::MissingLargest => {
                f.write_str("ACK bitmap does not acknowledge its largest packet")
            }

            Self::InvalidBitmap => f.write_str("ACK bitmap contains invalid packet numbers"),
        }
    }
}

impl std::error::Error for AckError {}

/// Canonical acknowledgment of authenticated DATA packets.
///
/// Bit i represents largest_acked - i.
/// Bits within each byte use least-significant-bit ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckFrame {
    largest_acked: u64,
    bitmap: [u8; ACK_BITMAP_LEN],
}

impl AckFrame {
    pub fn new(largest_acked: u64, bitmap: [u8; ACK_BITMAP_LEN]) -> Result<Self, AckError> {
        if largest_acked == 0 || largest_acked >= MAX_PACKET_NUMBER_EXCLUSIVE {
            return Err(AckError::InvalidLargest);
        }

        if bitmap[0] & 1 == 0 {
            return Err(AckError::MissingLargest);
        }

        // Packet number zero and arithmetic underflow
        // must never be represented by a set bit.
        let valid_bits = largest_acked.min(ACK_BITMAP_BITS as u64) as usize;

        if (valid_bits..ACK_BITMAP_BITS).any(|bit| bitmap[bit / 8] & (1_u8 << (bit % 8)) != 0) {
            return Err(AckError::InvalidBitmap);
        }

        Ok(Self {
            largest_acked,
            bitmap,
        })
    }

    pub fn largest_acked(&self) -> u64 {
        self.largest_acked
    }

    pub fn bitmap(&self) -> &[u8; ACK_BITMAP_LEN] {
        &self.bitmap
    }

    /// Check whether this snapshot acknowledges a packet.
    pub fn acknowledges(&self, packet_number: u64) -> bool {
        if packet_number == 0 {
            return false;
        }

        let Some(distance) = self.largest_acked.checked_sub(packet_number) else {
            return false;
        };

        if distance >= ACK_BITMAP_BITS as u64 {
            return false;
        }

        let bit = distance as usize;

        self.bitmap[bit / 8] & (1_u8 << (bit % 8)) != 0
    }

    /// Serialize the canonical ACK plaintext.
    ///
    /// Does not perform encryption.
    pub fn encode(&self) -> [u8; ACK_PLAINTEXT_LEN] {
        let mut output = [0_u8; ACK_PLAINTEXT_LEN];

        output[..8].copy_from_slice(&self.largest_acked.to_be_bytes());

        output[8..].copy_from_slice(&self.bitmap);

        output
    }

    /// Decode and validate ACK plaintext.
    ///
    /// The caller must authenticate the enclosing
    /// protected packet before using this frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, AckError> {
        if bytes.len() != ACK_PLAINTEXT_LEN {
            return Err(AckError::InvalidLength);
        }

        let largest_acked = u64::from_be_bytes(bytes[..8].try_into().expect("ACK length checked"));

        let bitmap = bytes[8..].try_into().expect("ACK length checked");

        Self::new(largest_acked, bitmap)
    }
}

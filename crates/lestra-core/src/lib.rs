//! Transport-independent protocol primitives.
//! Wire format and cryptographic negotiation will be specified before implementation.

/// Initial development protocol major version (not a stable wire format).
mod replay;

pub use replay::ReplayWindow;

pub const PROTOCOL_MAJOR_VERSION: u16 = 0;
pub const MAX_PACKET_NUMBER_EXCLUSIVE: u64 = 1_u64 << 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pre_specification() {
        assert_eq!(PROTOCOL_MAJOR_VERSION, 0);
    }
}

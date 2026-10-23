//! Transport-independent protocol primitives.
//! Wire format and cryptographic negotiation will be specified before implementation.

/// Initial development protocol major version (not a stable wire format).
pub const PROTOCOL_MAJOR_VERSION: u16 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pre_specification() {
        assert_eq!(PROTOCOL_MAJOR_VERSION, 0);
    }
}

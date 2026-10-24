#![no_main]
// Optional offline developer libFuzzer target; not part of normal CI.
use lestra_protocol_vectors::{decode_envelope, HEADER_LEN, MAX_UDP_PAYLOAD};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(pkt) = decode_envelope(bytes) {
        assert!((HEADER_LEN..=MAX_UDP_PAYLOAD).contains(&bytes.len()));
        assert_eq!(pkt.body.len() + HEADER_LEN, bytes.len());
        assert_eq!(pkt.header.as_ptr(), bytes.as_ptr());
    }
});

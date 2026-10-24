//! Structural framing tests; passing does not authenticate ciphertext.
use lestra_protocol_vectors::{decode_envelope, HEADER_LEN, MAX_UDP_PAYLOAD, AEAD_TAG_LEN};
use proptest::prelude::*;
use serde_json::Value;
const FIXTURE: &str = include_str!("../../../spec/v1/vectors/parser_cases.json");
fn fixtures() -> Value { serde_json::from_str(FIXTURE).expect("fixture JSON") }
fn buf(entry: &Value) -> Vec<u8> {
    hex::decode(entry["hex"].as_str().expect("hex fixture")).expect("hex")
}
#[test]
fn positive_binary_fixtures_are_borrowed_without_copies() {
    let fixture = fixtures();
    let positives = fixture["positive"].as_array().expect("positive array");
    assert_eq!(positives.len(), 7);
    for item in positives {
        let b = buf(item);
        let pkt = decode_envelope(&b).unwrap_or_else(|e| panic!("{}: {e:?}", item["name"]));
        assert_eq!(pkt.header.len(), HEADER_LEN);
        assert_eq!(pkt.body.len() + HEADER_LEN, b.len());
        assert_eq!(pkt.header.as_ptr(), b.as_ptr());
        assert_eq!(pkt.body.as_ptr(), b[HEADER_LEN..].as_ptr());
    }
}
#[test]
fn negative_binary_fixtures_fail_closed() {
    let fixture = fixtures();
    let negatives = fixture["negative"].as_array().expect("negative array");
    assert!(negatives.len() >= 20);
    for item in negatives {
        let b = buf(item);
        assert!(decode_envelope(&b).is_err(), "accepted {}", item["name"]);
    }
}
#[test]
fn packet_type_counter_mapping_is_strict_for_all_protected_types() {
    let fixture = fixtures();
    let negative = fixture["negative"].as_array().expect("negative array");
    for case in [
        "confirm-nonzero-packet-number",
        "ready-nonzero-packet-number",
        "data-zero-packet-number",
        "close-zero-packet-number",
    ] {
        let entry = negative.iter().find(|item| item["name"] == case)
            .expect("missing committed negative fixture");
        assert!(decode_envelope(&buf(entry)).is_err(), "{case}");
    }
    let positive = fixture["positive"].as_array().expect("positive array");
    for entry in positive.iter().skip(2) {
        assert!(decode_envelope(&buf(entry)).is_ok(), "{}", entry["name"]);
    }
}

#[test]
fn syntactically_valid_ciphertext_corruption_needs_aead() {
    let f = fixtures();
    let mut b = buf(&f["positive"][4]); // first DATA
    assert!(b.len() > HEADER_LEN + AEAD_TAG_LEN);
    b[HEADER_LEN] ^= 1;
    assert!(decode_envelope(&b).is_ok());
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]
    #[test]
    fn arbitrary_datagrams_have_safe_framing(
        bytes in proptest::collection::vec(any::<u8>(), 0..4097)
    ) {
        if let Ok(pkt) = decode_envelope(&bytes) {
            prop_assert!((HEADER_LEN..=MAX_UDP_PAYLOAD).contains(&bytes.len()));
            prop_assert_eq!(pkt.body.len() + HEADER_LEN, bytes.len());
            prop_assert_eq!(pkt.header.as_ptr(), bytes.as_ptr());
            prop_assert_eq!(pkt.body.as_ptr(), bytes[HEADER_LEN..].as_ptr());
            prop_assert!((1..=6).contains(&pkt.kind));
        }
    }
    #[test]
    fn a_false_claimed_size_is_never_accepted(
        body in proptest::collection::vec(any::<u8>(), 0..1300),
        claimed in any::<u16>(),
        kind in 1_u8..7_u8
    ) {
        let mut bytes = vec![0_u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(b"LSTR");
        bytes[4] = 1;
        bytes[5] = kind;
        bytes[15] = if kind == 1 { 0 } else { 1 };
        bytes[24..26].copy_from_slice(&claimed.to_be_bytes());
        bytes.extend_from_slice(&body);
        if usize::from(claimed) != body.len() {
            prop_assert!(decode_envelope(&bytes).is_err());
        }
    }
}

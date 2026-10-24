use lestra_codec::{
    AEAD_TAG_LEN, CodecError, DRAFT_WIRE_MAJOR, HEADER_LEN, MAX_DATAGRAM_LEN,
    MAX_PACKET_NUMBER_EXCLUSIVE, PacketHeader, PacketType, decode_packet, encode_header,
    encode_packet_into,
};

const FIXTURES: &str = include_str!("../../../spec/v1/vectors/parser_cases.json");

// No JSON/hex dependency in the production crate or test suite. Fixture-only
// extraction from a committed, fixed-format JSON file.
fn fixture_cases(section: &str) -> Vec<(String, Vec<u8>)> {
    let prefix = format!("\"{section}\": [");
    let entries = FIXTURES
        .split_once(&prefix)
        .expect("fixture section")
        .1
        .split_once(']')
        .expect("section terminator")
        .0;
    entries
        .split('{')
        .skip(1)
        .map(|part| {
            let name = part
                .split_once("\"name\": \"")
                .expect("name")
                .1
                .split('"')
                .next()
                .expect("name value");
            let hex = part
                .split_once("\"hex\": \"")
                .expect("hex")
                .1
                .split('"')
                .next()
                .expect("hex value");
            assert_eq!(hex.len() % 2, 0);
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture hex"))
                .collect();
            (name.to_owned(), bytes)
        })
        .collect()
}

fn header(kind: PacketType, cid: [u8; 8], number: u64) -> PacketHeader {
    PacketHeader {
        kind,
        destination_connection_id: cid,
        packet_number: number,
    }
}

#[test]
fn all_positive_wire_vectors_roundtrip() {
    let cases = fixture_cases("positive");
    assert_eq!(cases.len(), 7);
    for (name, packet) in cases {
        let decoded = decode_packet(&packet).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(decoded.raw_header.as_ptr(), packet.as_ptr());
        assert_eq!(decoded.body.as_ptr(), packet[HEADER_LEN..].as_ptr());

        let mut encoded = [0_u8; MAX_DATAGRAM_LEN];
        let output = encode_packet_into(decoded.header, decoded.body, &mut encoded).unwrap();
        assert_eq!(output, packet, "{name}");
        let mut raw_header = [0; HEADER_LEN];
        encode_header(decoded.header, decoded.body.len(), &mut raw_header).unwrap();
        assert_eq!(raw_header, *decoded.raw_header, "header AAD {name}");
    }
}

#[test]
fn all_negative_wire_vectors_are_rejected() {
    let cases = fixture_cases("negative");
    assert_eq!(cases.len(), 27);
    for (name, bytes) in cases {
        assert!(decode_packet(&bytes).is_err(), "invalid fixture {name}");
    }
}

#[test]
fn maximum_packet_and_out_of_bounds_rejected() {
    let hdr = header(PacketType::Data, [7; 8], 1);
    let body = [0x5a_u8; MAX_DATAGRAM_LEN - HEADER_LEN];
    let mut space = [0; MAX_DATAGRAM_LEN];
    let data = encode_packet_into(hdr, &body, &mut space).unwrap();
    assert_eq!(data.len(), MAX_DATAGRAM_LEN);
    assert_eq!(decode_packet(data).unwrap().body, &body);

    let oversized = vec![0_u8; MAX_DATAGRAM_LEN - HEADER_LEN + 1];
    assert_eq!(
        encode_packet_into(hdr, &oversized, &mut space),
        Err(CodecError::Oversized)
    );
}

#[test]
fn invalid_encoding_never_partially_modifies_buffers() {
    let confirm = header(PacketType::Confirm, [8; 8], 0);
    let body = [0_u8; AEAD_TAG_LEN];
    let mut small = [0xa5_u8; 41];
    assert_eq!(
        encode_packet_into(confirm, &body, &mut small),
        Err(CodecError::OutputTooSmall {
            required: 42,
            available: 41,
        })
    );
    assert_eq!(small, [0xa5_u8; 41]);

    let invalid = header(PacketType::Data, [8; 8], 0);
    let mut buffer = [0xa5; 128];
    assert_eq!(
        encode_packet_into(invalid, &body, &mut buffer),
        Err(CodecError::InvalidPacketNumber)
    );
    assert_eq!(buffer, [0xa5_u8; 128]);
    let mut aad = [0xa5; HEADER_LEN];
    assert_eq!(
        encode_header(invalid, body.len(), &mut aad),
        Err(CodecError::InvalidPacketNumber)
    );
    assert_eq!(aad, [0xa5_u8; HEADER_LEN]);
}

#[test]
fn type_counter_and_cid_constraints() {
    let cid = [9_u8; 8];
    let cases = [
        (header(PacketType::Initial, [0; 8], 0), 130, true),
        (header(PacketType::Initial, cid, 0), 130, false),
        (header(PacketType::Handshake, cid, 0), 82, true),
        (header(PacketType::Handshake, [0; 8], 0), 82, false),
        (header(PacketType::Confirm, cid, 0), 16, true),
        (header(PacketType::Confirm, cid, 1), 16, false),
        (header(PacketType::Ready, cid, 0), 16, true),
        (header(PacketType::Ready, cid, 1), 16, false),
        (header(PacketType::Data, cid, 1), 16, true),
        (header(PacketType::Data, cid, 0), 16, false),
        (header(PacketType::Close, cid, 1), 16, true),
        (header(PacketType::Close, cid, 0), 16, false),
        (
            header(PacketType::Data, cid, MAX_PACKET_NUMBER_EXCLUSIVE - 1),
            16,
            true,
        ),
        (
            header(PacketType::Data, cid, MAX_PACKET_NUMBER_EXCLUSIVE),
            16,
            false,
        ),
        (header(PacketType::Data, cid, 1), 15, false),
        (header(PacketType::Close, cid, 1), 17, false),
    ];
    for (header, len, success) in cases {
        let mut buffer = [0; HEADER_LEN];
        assert_eq!(
            encode_header(header, len, &mut buffer).is_ok(),
            success,
            "{header:?}"
        );
    }
}

#[test]
fn framing_does_not_authenticate_ciphertext() {
    let (_, mut data) = fixture_cases("positive")
        .into_iter()
        .find(|(name, _)| name == "data-2")
        .unwrap();
    data[HEADER_LEN] ^= 1;
    assert!(decode_packet(&data).is_ok());
}

#[test]
fn explicit_version_type_and_flags_errors() {
    let (_, original) = fixture_cases("positive")
        .into_iter()
        .find(|(name, _)| name == "confirm-0")
        .unwrap();
    let mut v = original.clone();
    v[4] = DRAFT_WIRE_MAJOR + 1;
    assert_eq!(decode_packet(&v), Err(CodecError::UnsupportedVersion(2)));
    v = original.clone();
    v[5] = 200;
    assert_eq!(decode_packet(&v), Err(CodecError::InvalidType(200)));
    v = original;
    v[7] = 1;
    assert_eq!(decode_packet(&v), Err(CodecError::ReservedFlags));
}

#[test]
fn deterministic_mutations_are_bounded_and_non_panicking() {
    let (_, initial) = fixture_cases("positive").into_iter().next().unwrap();
    for offset in 0..initial.len() {
        for value in [0_u8, 1, 127, 255] {
            let mut input = initial.clone();
            input[offset] = value;
            if let Ok(packet) = decode_packet(&input) {
                let mut buffer = [0; MAX_DATAGRAM_LEN];
                let roundtrip =
                    encode_packet_into(packet.header, packet.body, &mut buffer).unwrap();
                assert_eq!(roundtrip, input);
            }
        }
    }
}

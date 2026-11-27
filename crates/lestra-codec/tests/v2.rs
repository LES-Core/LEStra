use lestra_codec::{
    CodecError, HEADER_LEN, MAX_PACKET_NUMBER_EXCLUSIVE,
    v2::{self, ACK_BODY_LEN, ACK_PACKET_LEN, PacketHeader, PacketType},
};

fn ack_header() -> PacketHeader {
    PacketHeader {
        kind: PacketType::Ack,
        destination_connection_id: [1; 8],
        packet_number: 7,
    }
}

#[test]
fn ack_packet_has_canonical_wire_format() {
    let mut output = [0_u8; ACK_PACKET_LEN];

    let bytes = v2::encode_packet_into(ack_header(), &[0xAB; ACK_BODY_LEN], &mut output).unwrap();

    assert_eq!(bytes.len(), 178);
    assert_eq!(&bytes[..4], b"LSTR");
    assert_eq!(bytes[4], 2);
    assert_eq!(bytes[5], 7);
    assert_eq!(&bytes[6..8], &[0, 0]);
    assert_eq!(&bytes[24..26], &[0, 152]);

    let decoded = v2::decode_packet(bytes).unwrap();

    assert_eq!(decoded.header, ack_header());
    assert_eq!(decoded.body, &[0xAB; ACK_BODY_LEN]);
    assert_eq!(decoded.raw_header, &bytes[..HEADER_LEN]);
}

#[test]
fn ack_requires_nonzero_connection_id() {
    let header = PacketHeader {
        destination_connection_id: [0; 8],
        ..ack_header()
    };

    let mut output = [0_u8; HEADER_LEN];

    assert_eq!(
        v2::encode_header(header, ACK_BODY_LEN, &mut output,),
        Err(CodecError::InvalidConnectionId)
    );
}

#[test]
fn ack_requires_valid_protected_packet_number() {
    let mut output = [0_u8; HEADER_LEN];

    for pn in [0, MAX_PACKET_NUMBER_EXCLUSIVE, u64::MAX] {
        let header = PacketHeader {
            packet_number: pn,
            ..ack_header()
        };

        assert_eq!(
            v2::encode_header(header, ACK_BODY_LEN, &mut output,),
            Err(CodecError::InvalidPacketNumber)
        );
    }
}

#[test]
fn ack_requires_exact_protected_body_length() {
    let mut output = [0xAA_u8; HEADER_LEN];

    for len in [ACK_BODY_LEN - 1, ACK_BODY_LEN + 1] {
        assert_eq!(
            v2::encode_header(ack_header(), len, &mut output,),
            Err(CodecError::InvalidBodyLength)
        );
    }

    assert_eq!(output, [0xAA; HEADER_LEN]);
}

#[test]
fn v1_decoder_rejects_v2_ack() {
    let mut output = [0_u8; ACK_PACKET_LEN];

    let bytes = v2::encode_packet_into(ack_header(), &[0; ACK_BODY_LEN], &mut output).unwrap();

    assert!(matches!(
        lestra_codec::decode_packet(bytes),
        Err(CodecError::UnsupportedVersion(2))
    ));
}

#[test]
fn v2_decoder_rejects_v1_data() {
    let header = lestra_codec::PacketHeader {
        kind: lestra_codec::PacketType::Data,
        destination_connection_id: [1; 8],
        packet_number: 1,
    };

    let mut output = [0_u8; 42];

    let bytes = lestra_codec::encode_packet_into(header, &[0; 16], &mut output).unwrap();

    assert!(matches!(
        v2::decode_packet(bytes),
        Err(CodecError::UnsupportedVersion(1))
    ));
}

#[test]
fn v2_preserves_existing_data_framing_rules() {
    let header = PacketHeader {
        kind: PacketType::Data,
        destination_connection_id: [1; 8],
        packet_number: 1,
    };

    let mut output = [0_u8; 42];

    let bytes = v2::encode_packet_into(header, &[0; 16], &mut output).unwrap();

    let decoded = v2::decode_packet(bytes).unwrap();

    assert_eq!(decoded.header, header);
    assert_eq!(decoded.body.len(), 16);
}

#[test]
fn insufficient_output_space_leaves_buffer_unchanged() {
    let mut output = [0xAA_u8; ACK_PACKET_LEN - 1];

    assert_eq!(
        v2::encode_packet_into(ack_header(), &[0; ACK_BODY_LEN], &mut output,),
        Err(CodecError::OutputTooSmall {
            required: ACK_PACKET_LEN,
            available: ACK_PACKET_LEN - 1,
        })
    );

    assert_eq!(output, [0xAA; ACK_PACKET_LEN - 1]);
}

#[test]
fn decoder_rejects_malformed_ack_header() {
    let mut output = [0_u8; ACK_PACKET_LEN];

    v2::encode_packet_into(ack_header(), &[0; ACK_BODY_LEN], &mut output).unwrap();

    let mut malformed = output;
    malformed[6] = 1;

    assert_eq!(
        v2::decode_packet(&malformed),
        Err(CodecError::ReservedFlags)
    );

    let mut malformed = output;
    malformed[24..26].fill(0);

    assert_eq!(
        v2::decode_packet(&malformed),
        Err(CodecError::LengthMismatch)
    );

    let mut malformed = output;
    malformed[5] = 255;

    assert_eq!(
        v2::decode_packet(&malformed),
        Err(CodecError::InvalidType(255))
    );
}

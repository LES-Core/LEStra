use lestra_codec::{
    MAX_PACKET_NUMBER_EXCLUSIVE,
    v2::{ACK_BITMAP_LEN, ACK_PLAINTEXT_LEN, AckError, AckFrame},
};

#[test]
fn ack_round_trip_preserves_bitmap() {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 0x17;

    let ack = AckFrame::new(104, bitmap).unwrap();

    let encoded = ack.encode();

    assert_eq!(encoded.len(), ACK_PLAINTEXT_LEN);
    assert_eq!(&encoded[..8], &104_u64.to_be_bytes());
    assert_eq!(encoded[8], 0x17);

    assert_eq!(AckFrame::decode(&encoded), Ok(ack));
}

#[test]
fn acknowledges_only_set_packet_numbers() {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 0x17;

    let ack = AckFrame::new(104, bitmap).unwrap();

    for pn in [100, 102, 103, 104] {
        assert!(ack.acknowledges(pn));
    }

    for pn in [0, 99, 101, 105, u64::MAX] {
        assert!(!ack.acknowledges(pn));
    }
}

#[test]
fn bitmap_has_exact_1024_packet_window() {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 1;
    bitmap[127] = 0x80;

    let ack = AckFrame::new(2000, bitmap).unwrap();

    assert!(ack.acknowledges(2000));
    assert!(ack.acknowledges(977));

    assert!(!ack.acknowledges(976));
    assert!(!ack.acknowledges(2001));
}

#[test]
fn rejects_invalid_largest_packet_number() {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 1;

    for pn in [0, MAX_PACKET_NUMBER_EXCLUSIVE, u64::MAX] {
        assert_eq!(AckFrame::new(pn, bitmap), Err(AckError::InvalidLargest));
    }

    assert!(AckFrame::new(MAX_PACKET_NUMBER_EXCLUSIVE - 1, bitmap,).is_ok());
}

#[test]
fn largest_packet_must_be_acknowledged() {
    let bitmap = [0_u8; ACK_BITMAP_LEN];

    assert_eq!(AckFrame::new(100, bitmap), Err(AckError::MissingLargest));
}

#[test]
fn rejects_bits_for_zero_or_underflow() {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 0b0000_0011;

    assert_eq!(AckFrame::new(1, bitmap), Err(AckError::InvalidBitmap));

    bitmap[0] = 1;
    bitmap[127] = 0x80;

    assert_eq!(AckFrame::new(1023, bitmap), Err(AckError::InvalidBitmap));

    assert!(AckFrame::new(1024, bitmap).is_ok());
}

#[test]
fn rejects_noncanonical_plaintext_lengths() {
    assert_eq!(
        AckFrame::decode(&[0_u8; ACK_PLAINTEXT_LEN - 1],),
        Err(AckError::InvalidLength)
    );

    assert_eq!(
        AckFrame::decode(&[0_u8; ACK_PLAINTEXT_LEN + 1],),
        Err(AckError::InvalidLength)
    );
}

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};

const FIXTURE: &str = include_str!("../../../spec/v1/vectors/native_udp_v2_ack.hex");

fn key() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

fn nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];

    nonce[4..].copy_from_slice(&7_u64.to_le_bytes());

    nonce
}

fn plaintext() -> [u8; 136] {
    let mut bytes = [0_u8; 136];

    bytes[..8].copy_from_slice(&104_u64.to_be_bytes());

    bytes[8] = 0x17;

    bytes
}

#[test]
fn independently_verifies_v2_ack_fixture() {
    let packet = hex::decode(FIXTURE.trim()).unwrap();

    assert_eq!(packet.len(), 178);

    let header = &packet[..26];
    let ciphertext = &packet[26..];

    let expected_header =
        hex::decode("4c53545202070000112233445566778800000000000000070098").unwrap();

    assert_eq!(header, expected_header.as_slice());

    let key = key();
    let nonce = nonce();

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .unwrap();

    assert_eq!(plain.as_slice(), &plaintext());

    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext(),
                aad: header,
            },
        )
        .unwrap();

    assert_eq!(encrypted.as_slice(), ciphertext);
}

#[test]
fn ack_fixture_authenticates_every_header_byte() {
    let packet = hex::decode(FIXTURE.trim()).unwrap();

    let key = key();
    let nonce = nonce();

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    for offset in 0..26 {
        let mut modified = packet.clone();

        modified[offset] ^= 1;

        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &modified[26..],
                        aad: &modified[..26],
                    },
                )
                .is_err(),
            "header byte {offset} was not authenticated"
        );
    }
}

#[test]
fn ack_fixture_rejects_ciphertext_and_tag_tampering() {
    let packet = hex::decode(FIXTURE.trim()).unwrap();

    let key = key();
    let nonce = nonce();

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    for offset in 26..packet.len() {
        let mut modified = packet.clone();

        modified[offset] ^= 1;

        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &modified[26..],
                        aad: &modified[..26],
                    },
                )
                .is_err()
        );
    }
}

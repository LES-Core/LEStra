//! Independent verification of LEStra's deterministic Noise IK and AEAD fixtures.
//! TEST-ONLY static/ephemeral secrets are public. Never use them in deployed systems.
//! The "risky-raw-split" feature is restricted to this isolated test crate.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde_json::Value;
use snow::{Builder, params::NoiseParams};

const NOISE_NAME: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const HEADER_LEN: usize = 26;
const MAX_UDP: usize = 1200;
const FIXTURE: &str = include_str!("../../../spec/v1/vectors/native_udp_ik.json");

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("valid committed fixture")
}

fn hex_field(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("required hex field")).expect("fixture hex")
}

fn nonce(packet_number: u64) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&packet_number.to_le_bytes());
    bytes
}

#[test]
fn noise_ik_transcript_matches_reference() -> TestResult {
    let v = fixture();
    let hs = &v["handshake"];
    let static_keys = &v["static_test_keys"];
    let ephemeral_keys = &v["ephemeral_test_keys"];
    let params: NoiseParams = NOISE_NAME.parse()?;

    let prologue = hex_field(&v, "prologue_hex");
    let client_static = hex_field(static_keys, "client_private_hex");
    let client_public = hex_field(static_keys, "client_public_hex");
    let server_static = hex_field(static_keys, "server_private_hex");
    let server_public = hex_field(static_keys, "server_public_hex");
    let client_ephemeral = hex_field(ephemeral_keys, "client_private_hex");
    let server_ephemeral = hex_field(ephemeral_keys, "server_private_hex");

    let mut initiator = Builder::new(params.clone())
        .local_private_key(&client_static)?
        .remote_public_key(&server_public)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&client_ephemeral)
        .build_initiator()?;
    let mut responder = Builder::new(params)
        .local_private_key(&server_static)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&server_ephemeral)
        .build_responder()?;

    let mut first_payload = hex_field(&hs["initial"], "header_hex");
    first_payload.extend(hex_field(&v["cids"], "client_hex"));
    let mut out = [0_u8; 256];
    let len1 = initiator.write_message(&first_payload, &mut out)?;
    assert_eq!(len1, 130);
    assert_eq!(&out[..len1], hex_field(&hs["initial"], "noise_message_hex"));
    assert_eq!(first_payload.len(), 34);
    let mut received = [0_u8; 128];
    let count1 = responder.read_message(&out[..len1], &mut received)?;
    assert_eq!(&received[..count1], first_payload);
    assert_eq!(responder.get_remote_static(), Some(client_public.as_slice()));

    let mut second_payload = hex_field(&hs["response"], "header_hex");
    second_payload.extend(hex_field(&v["cids"], "server_hex"));
    let len2 = responder.write_message(&second_payload, &mut out)?;
    assert_eq!(len2, 82);
    assert_eq!(&out[..len2], hex_field(&hs["response"], "noise_message_hex"));
    let count2 = initiator.read_message(&out[..len2], &mut received)?;
    assert_eq!(&received[..count2], second_payload);
    assert!(initiator.is_handshake_finished());
    assert!(responder.is_handshake_finished());
    assert_eq!(initiator.get_handshake_hash(), responder.get_handshake_hash());
    assert_eq!(initiator.get_handshake_hash(), hex_field(hs, "handshake_hash_hex"));

    // This is an isolated verification helper, NOT a production key export API.
    let (client_to_server, server_to_client) = initiator.dangerously_get_raw_split();
    let (responder_c2s, responder_s2c) = responder.dangerously_get_raw_split();
    assert_eq!(client_to_server, responder_c2s);
    assert_eq!(server_to_client, responder_s2c);
    assert_eq!(client_to_server.as_slice(), hex_field(hs, "client_to_server_key_hex"));
    assert_eq!(server_to_client.as_slice(), hex_field(hs, "server_to_client_key_hex"));
    assert_ne!(client_to_server, server_to_client);
    Ok(())
}

#[test]
fn protected_packets_authenticate_entire_header() -> TestResult {
    let v = fixture();
    let hs = &v["handshake"];
    let key_c2s = hex_field(hs, "client_to_server_key_hex");
    let key_s2c = hex_field(hs, "server_to_client_key_hex");
    let cid_client = hex_field(&v["cids"], "client_hex");
    let cid_server = hex_field(&v["cids"], "server_hex");

    for packet in v["protected_packets"].as_array().expect("array") {
        let kind = packet["type"].as_str().expect("type");
        let header = hex_field(packet, "header_hex");
        let plaintext = hex_field(packet, "plaintext_hex");
        let ciphertext = hex_field(packet, "ciphertext_hex");
        let full = hex_field(packet, "packet_hex");
        let pn = packet["packet_number"].as_u64().expect("counter");

        assert_eq!(header.len(), HEADER_LEN);
        assert_eq!(&header[0..4], b"LSTR");
        assert_eq!(header[4], 1);
        assert_eq!(&header[6..8], &[0_u8; 2]);
        assert_eq!(u64::from_be_bytes(header[16..24].try_into()?), pn);
        assert_eq!(usize::from(u16::from_be_bytes(header[24..26].try_into()?)), ciphertext.len());
        assert_eq!(full, [&header[..], &ciphertext[..]].concat());
        assert!(full.len() <= MAX_UDP);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let to_server = &header[8..16] == cid_server.as_slice();
        let to_client = &header[8..16] == cid_client.as_slice();
        assert!(to_server ^ to_client);
        match kind {
            "CONFIRM" => assert_eq!((header[5], pn, to_server), (3, 0, true)),
            "READY" => assert_eq!((header[5], pn, to_client), (6, 0, true)),
            "DATA" => assert_eq!(header[5], 4),
            "CLOSE" => assert_eq!(header[5], 5),
            _ => panic!("unexpected protected fixture type"),
        }

        let cipher = ChaCha20Poly1305::new_from_slice(if to_server { &key_c2s } else { &key_s2c })
            .expect("fixture keys are 32 bytes");
        let nonce_bytes = nonce(pn);
        let produced = cipher.encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: &plaintext, aad: &header },
        ).expect("encrypt reference");
        assert_eq!(produced, ciphertext, "AEAD mismatch for {kind}");
        let recovered = cipher.decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: &ciphertext, aad: &header },
        ).expect("decrypt reference");
        assert_eq!(recovered, plaintext);

        let mut bad_header = header.clone();
        bad_header[11] ^= 1;
        assert!(cipher.decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: &ciphertext, aad: &bad_header },
        ).is_err());

        let mut bad_ciphertext = ciphertext.clone();
        let last = bad_ciphertext.len() - 1;
        bad_ciphertext[last] ^= 1;
        assert!(cipher.decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: &bad_ciphertext, aad: &header },
        ).is_err());
    }
    Ok(())
}

#[test]
fn wrong_server_pin_rejects_noise_handshake() -> TestResult {
    let v = fixture();
    let statics = &v["static_test_keys"];
    let ephemeral = &v["ephemeral_test_keys"];
    let params: NoiseParams = NOISE_NAME.parse()?;
    let prologue = hex_field(&v, "prologue_hex");
    let client_static = hex_field(statics, "client_private_hex");
    let server_static = hex_field(statics, "server_private_hex");
    let client_ephemeral = hex_field(ephemeral, "client_private_hex");
    let fake_server_pin = [7_u8; 32];

    let mut client = Builder::new(params.clone())
        .local_private_key(&client_static)?
        .remote_public_key(&fake_server_pin)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&client_ephemeral)
        .build_initiator()?;
    let mut server = Builder::new(params)
        .local_private_key(&server_static)?
        .prologue(&prologue)?
        .build_responder()?;

    let mut message = [0_u8; 256];
    let length = client.write_message(&[0_u8; 34], &mut message)?;
    let mut reply = [0_u8; 128];
    assert!(server.read_message(&message[..length], &mut reply).is_err());
    Ok(())
}

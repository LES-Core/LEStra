use lestra_codec::{HEADER_LEN, MAX_DATAGRAM_LEN};
use serde_json::Value;
use snow::{Builder, params::NoiseParams};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

const FIXTURE: &str = include_str!("../../../spec/v1/vectors/native_udp_ik.json");

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn hex_field(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("required hex field")).expect("valid fixture hex")
}

#[test]
fn explicit_aad_matches_reference_vectors() -> TestResult {
    let v: Value = serde_json::from_str(FIXTURE)?;

    let hs = &v["handshake"];
    let static_keys = &v["static_test_keys"];
    let ephemeral_keys = &v["ephemeral_test_keys"];
    let cids = &v["cids"];

    let params: NoiseParams = PATTERN.parse()?;

    let prologue = hex_field(&v, "prologue_hex");

    let client_static = hex_field(static_keys, "client_private_hex");
    let server_static = hex_field(static_keys, "server_private_hex");
    let server_public = hex_field(static_keys, "server_public_hex");

    let client_ephemeral = hex_field(ephemeral_keys, "client_private_hex");
    let server_ephemeral = hex_field(ephemeral_keys, "server_private_hex");

    let client_cid = hex_field(cids, "client_hex");
    let server_cid = hex_field(cids, "server_hex");

    let mut client = Builder::new(params.clone())
        .local_private_key(&client_static)?
        .remote_public_key(&server_public)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&client_ephemeral)
        .build_initiator()?;

    let mut server = Builder::new(params)
        .local_private_key(&server_static)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&server_ephemeral)
        .build_responder()?;

    let mut initial = hex_field(&hs["initial"], "header_hex");
    initial.extend_from_slice(&client_cid);

    let mut response = hex_field(&hs["response"], "header_hex");
    response.extend_from_slice(&server_cid);

    let mut encrypted = [0_u8; MAX_DATAGRAM_LEN];
    let mut decrypted = [0_u8; MAX_DATAGRAM_LEN];

    let len = client.write_message(&initial, &mut encrypted)?;

    assert_eq!(
        &encrypted[..len],
        hex_field(&hs["initial"], "noise_message_hex")
    );

    let len = server.read_message(&encrypted[..len], &mut decrypted)?;

    assert_eq!(&decrypted[..len], initial.as_slice());

    let len = server.write_message(&response, &mut encrypted)?;

    assert_eq!(
        &encrypted[..len],
        hex_field(&hs["response"], "noise_message_hex")
    );

    let len = client.read_message(&encrypted[..len], &mut decrypted)?;

    assert_eq!(&decrypted[..len], response.as_slice());

    assert!(client.is_handshake_finished());
    assert!(server.is_handshake_finished());

    assert_eq!(client.get_handshake_hash(), server.get_handshake_hash());

    let client = client.into_stateless_transport_mode()?;
    let server = server.into_stateless_transport_mode()?;

    for packet in v["protected_packets"]
        .as_array()
        .expect("protected packet vectors")
    {
        let header = hex_field(packet, "header_hex");
        let plaintext = hex_field(packet, "plaintext_hex");
        let expected = hex_field(packet, "ciphertext_hex");

        let pn = packet["packet_number"].as_u64().expect("packet number");

        assert_eq!(header.len(), HEADER_LEN);

        let (sender, receiver) = if header[8..16] == server_cid[..] {
            (&client, &server)
        } else {
            assert_eq!(header[8..16], client_cid[..]);
            (&server, &client)
        };

        let len = sender.write_message_with_ad(pn, &header, &plaintext, &mut encrypted)?;

        assert_eq!(&encrypted[..len], expected.as_slice());

        let decoded =
            receiver.read_message_with_ad(pn, &header, &encrypted[..len], &mut decrypted)?;

        assert_eq!(&decrypted[..decoded], plaintext.as_slice());

        // Every header byte must be authenticated.
        for index in 0..HEADER_LEN {
            let mut tampered = header.clone();
            tampered[index] ^= 1;

            assert!(
                receiver
                    .read_message_with_ad(pn, &tampered, &encrypted[..len], &mut decrypted,)
                    .is_err()
            );
        }

        // Reject an incorrect nonce.
        assert!(
            receiver
                .read_message_with_ad(pn ^ 1, &header, &encrypted[..len], &mut decrypted,)
                .is_err()
        );

        // Reject ciphertext encrypted in the opposite direction.
        assert!(
            sender
                .read_message_with_ad(pn, &header, &encrypted[..len], &mut decrypted,)
                .is_err()
        );

        // Reject a modified ciphertext or authentication tag.
        for index in 0..len {
            encrypted[index] ^= 1;

            assert!(
                receiver
                    .read_message_with_ad(pn, &header, &encrypted[..len], &mut decrypted,)
                    .is_err()
            );

            encrypted[index] ^= 1;
        }
    }

    // Reject oversized incoming Noise messages.
    let oversized = vec![0_u8; 65_536];

    assert!(matches!(
        server.read_message_with_ad(0, &[0_u8; HEADER_LEN], &oversized, &mut decrypted,),
        Err(snow::Error::Input)
    ));

    Ok(())
}

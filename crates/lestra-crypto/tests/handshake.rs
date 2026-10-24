use std::net::SocketAddr;

use lestra_crypto::{ClientStart, HandshakeError, INITIAL_SIZE, RESPONSE_SIZE, ServerStart};
use snow::{Builder, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn keys() -> (snow::Keypair, snow::Keypair) {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse().unwrap();
    let builder = Builder::new(params);
    (
        builder.generate_keypair().unwrap(),
        builder.generate_keypair().unwrap(),
    )
}

fn key32(key: &[u8]) -> [u8; 32] {
    key.try_into().expect("Noise X25519 test key length")
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn pinned_noise_ik_exchange_binds_transcript_and_both_cids() -> TestResult {
    let (client_key, server_key) = keys();
    let client_private = key32(&client_key.private);
    let server_private = key32(&server_key.private);
    let server_public = key32(&server_key.public);
    let client_public = key32(&client_key.public);
    let client_cid = [11_u8; 8];
    let server_cid = [22_u8; 8];

    let client = ClientStart::new(&client_private, &server_public, client_cid, addr(3456))?;
    let pending = client.start()?;
    assert_eq!(pending.initial().len(), INITIAL_SIZE);
    let repeated = pending.initial().to_vec();
    assert_eq!(&repeated, pending.initial());
    let server = ServerStart::new(&server_private, client_public, server_cid)?;
    let server = server.accept_initial(addr(1234), pending.initial())?;
    assert_eq!(server.response().len(), RESPONSE_SIZE);

    let verified_client = pending.accept_response(addr(3456), server.response())?;
    let verified_server = server.verified_noise();
    assert!(verified_client.noise_complete());
    assert!(verified_server.noise_complete());
    assert_eq!(
        verified_client.transcript_hash(),
        verified_server.transcript_hash()
    );
    assert_eq!(verified_client.transcript_hash().len(), 32);
    assert_eq!(verified_client.local_receive_cid(), client_cid);
    assert_eq!(verified_client.remote_receive_cid(), server_cid);
    assert_eq!(verified_server.local_receive_cid(), server_cid);
    assert_eq!(verified_server.remote_receive_cid(), client_cid);
    assert_eq!(verified_client.remote_endpoint(), addr(3456));
    assert_eq!(verified_server.remote_endpoint(), addr(1234));
    Ok(())
}

#[test]
fn unauthorized_client_is_rejected_before_any_response() -> TestResult {
    let (client_key, server_key) = keys();
    let (another_key, _) = keys();
    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;
    let responder = ServerStart::new(
        &key32(&server_key.private),
        key32(&another_key.public),
        [2; 8],
    )?;
    assert!(matches!(
        responder.accept_initial(addr(4000), client.initial()),
        Err(HandshakeError::UnauthorizedClient)
    ));
    Ok(())
}

#[test]
fn incorrect_pinned_server_identity_fails_noise_authentication() -> TestResult {
    let (client_key, actual_server) = keys();
    let (_, wrong_server) = keys();
    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&wrong_server.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;
    let responder = ServerStart::new(
        &key32(&actual_server.private),
        key32(&client_key.public),
        [2; 8],
    )?;
    assert!(matches!(
        responder.accept_initial(addr(4000), client.initial()),
        Err(HandshakeError::Noise(_))
    ));
    Ok(())
}

#[test]
fn modified_noise_ciphertext_is_rejected() -> TestResult {
    let (client_key, server_key) = keys();
    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;
    let responder = ServerStart::new(
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?;
    let mut tampered = *client.initial();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        responder.accept_initial(addr(4000), &tampered),
        Err(HandshakeError::Noise(_))
    ));
    Ok(())
}

#[test]
fn wrong_response_endpoint_or_cid_fails_closed() -> TestResult {
    let (client_key, server_key) = keys();
    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;
    let server = ServerStart::new(
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?
    .accept_initial(addr(4000), client.initial())?;
    assert!(matches!(
        client.accept_response(addr(5001), server.response()),
        Err(HandshakeError::UnexpectedPeer)
    ));

    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;
    let server = ServerStart::new(
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?
    .accept_initial(addr(4000), client.initial())?;
    let mut changed = *server.response();
    changed[15] ^= 1;
    assert!(matches!(
        client.accept_response(addr(5000), &changed),
        Err(HandshakeError::UnexpectedPacket)
    ));
    Ok(())
}

#[test]
fn rejects_zero_cids_and_truncated_initial() -> TestResult {
    let (client_key, server_key) = keys();
    assert!(matches!(
        ClientStart::new(
            &key32(&client_key.private),
            &key32(&server_key.public),
            [0; 8],
            addr(4000)
        ),
        Err(HandshakeError::InvalidConnectionId)
    ));
    assert!(matches!(
        ServerStart::new(
            &key32(&server_key.private),
            key32(&client_key.public),
            [0; 8]
        ),
        Err(HandshakeError::InvalidConnectionId)
    ));

    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(4000),
    )?
    .start()?;
    let server = ServerStart::new(
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?;
    assert!(matches!(
        server.accept_initial(addr(5000), &client.initial()[..25]),
        Err(HandshakeError::Codec(_))
    ));
    Ok(())
}

use std::net::SocketAddr;

use lestra_codec::{PacketType, decode_packet};
use lestra_crypto::{
    ClientAwaitingReady, ClientStart, PacketProtectionError, ServerAwaitingConfirm, ServerStart,
};
use snow::{Builder, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn pending_pair() -> Result<(ClientAwaitingReady, ServerAwaitingConfirm), Box<dyn std::error::Error>>
{
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    let builder = Builder::new(params);

    let client_key = builder.generate_keypair()?;
    let server_key = builder.generate_keypair()?;

    let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;

    let client_public: [u8; 32] = client_key.public.as_slice().try_into()?;

    let server_private: [u8; 32] = server_key.private.as_slice().try_into()?;

    let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

    let client_addr = SocketAddr::from(([127, 0, 0, 1], 4000));

    let server_addr = SocketAddr::from(([127, 0, 0, 1], 5000));

    let client = ClientStart::new(&client_private, &server_public, [1; 8], server_addr)?.start()?;

    let server = ServerStart::new(&server_private, client_public, [2; 8])?
        .accept_initial(client_addr, client.initial())?;

    let client = client
        .accept_response(server_addr, server.response())?
        .start_confirmation()?;

    let server = server.await_confirmation()?;

    Ok((client, server))
}

#[test]
fn full_handshake_establishes_both_peers() -> TestResult {
    let (mut client, mut server) = pending_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    server.accept_confirm(client_addr, client.confirm())?;

    let (server, ready) = server.into_established()?;

    let packet = decode_packet(&ready)?;

    assert_eq!(packet.header.kind, PacketType::Ready);
    assert_eq!(packet.header.packet_number, 0);
    assert_eq!(packet.header.destination_connection_id, [1; 8]);

    client.accept_ready(server_addr, &ready)?;

    let client = client.into_established()?;

    assert_eq!(client.local_receive_cid(), server.remote_receive_cid());

    assert_eq!(client.remote_receive_cid(), server.local_receive_cid());

    assert_eq!(client.remote_endpoint(), server_addr);
    assert_eq!(server.remote_endpoint(), client_addr);

    Ok(())
}

#[test]
fn cannot_establish_without_confirmation() -> TestResult {
    let (client, server) = pending_pair()?;

    assert!(matches!(
        client.into_established(),
        Err(PacketProtectionError::ConfirmationRequired)
    ));

    assert!(matches!(
        server.into_established(),
        Err(PacketProtectionError::ConfirmationRequired)
    ));

    Ok(())
}

#[test]
fn invalid_confirm_preserves_pending_server() -> TestResult {
    let (client, mut server) = pending_pair()?;

    let source = server.remote_endpoint();

    let mut invalid = *client.confirm();

    *invalid.last_mut().unwrap() ^= 1;

    assert!(matches!(
        server.accept_confirm(source, &invalid),
        Err(PacketProtectionError::Noise(_))
    ));

    server.accept_confirm(source, client.confirm())?;

    assert!(server.into_established().is_ok());

    Ok(())
}

#[test]
fn invalid_ready_preserves_pending_client() -> TestResult {
    let (mut client, mut server) = pending_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    server.accept_confirm(client_addr, client.confirm())?;

    let (_, ready) = server.into_established()?;

    let mut invalid = ready;

    *invalid.last_mut().unwrap() ^= 1;

    assert!(matches!(
        client.accept_ready(server_addr, &invalid),
        Err(PacketProtectionError::Noise(_))
    ));

    client.accept_ready(server_addr, &ready)?;

    assert!(client.into_established().is_ok());

    Ok(())
}

#[test]
fn duplicate_confirm_reuses_cached_ready() -> TestResult {
    let (mut client, mut server) = pending_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    server.accept_confirm(client_addr, client.confirm())?;

    let (mut server, ready) = server.into_established()?;

    // Simulate a lost READY packet.
    let retried = server
        .retry_ready(client_addr, client.confirm())
        .expect("cached READY");

    assert_eq!(retried, &ready);

    client.accept_ready(server_addr, retried)?;

    assert!(client.into_established().is_ok());

    Ok(())
}

#[test]
fn ready_retry_requires_exact_packet_and_endpoint() -> TestResult {
    let (client, mut server) = pending_pair()?;

    let source = server.remote_endpoint();

    server.accept_confirm(source, client.confirm())?;

    let (mut server, ready) = server.into_established()?;

    let wrong_source = SocketAddr::from(([127, 0, 0, 1], 9999));

    let mut invalid = *client.confirm();

    invalid[8] ^= 1;

    assert!(server.retry_ready(source, &invalid).is_none());

    assert!(server.retry_ready(wrong_source, client.confirm()).is_none());

    for _ in 0..5 {
        assert_eq!(server.retry_ready(source, client.confirm()), Some(&ready));
    }

    assert!(server.retry_ready(source, client.confirm()).is_none());

    Ok(())
}

#[test]
fn duplicate_ready_is_rejected() -> TestResult {
    let (mut client, mut server) = pending_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    server.accept_confirm(client_addr, client.confirm())?;

    let (_, ready) = server.into_established()?;

    client.accept_ready(server_addr, &ready)?;

    assert!(matches!(
        client.accept_ready(server_addr, &ready),
        Err(PacketProtectionError::ReplayRejected)
    ));

    assert!(client.into_established().is_ok());

    Ok(())
}

#[test]
fn expired_confirmation_cache_cannot_retry_ready() -> TestResult {
    let (client, mut server) = pending_pair()?;

    let source = server.remote_endpoint();

    server.accept_confirm(source, client.confirm())?;

    let (mut server, _) = server.into_established()?;

    server.discard_confirmation_cache();

    assert!(server.retry_ready(source, client.confirm()).is_none());

    Ok(())
}

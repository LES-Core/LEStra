use std::net::SocketAddr;

use lestra_codec::{CodecError, MAX_DATAGRAM_LEN, PacketType, decode_packet};
use lestra_crypto::{
    CLOSE_SIZE, ClientAwaitingReady, ClientStart, EstablishedSession, MAX_DATA_SIZE,
    PacketProtectionError, ReceiveEvent, ServerAwaitingConfirm, ServerStart,
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

fn established_pair() -> Result<(EstablishedSession, EstablishedSession), Box<dyn std::error::Error>>
{
    let (mut client, mut server) = pending_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    server.accept_confirm(client_addr, client.confirm())?;

    let (server, ready) = server.into_established()?;

    client.accept_ready(server_addr, &ready)?;

    Ok((client.into_established()?, server))
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

#[test]
fn established_peers_exchange_data() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let client_addr = server.remote_endpoint();
    let server_addr = client.remote_endpoint();

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(b"hello server", &mut packet)?;

    let decoded = decode_packet(&packet[..len])?;

    assert_eq!(decoded.header.kind, PacketType::Data);
    assert_eq!(decoded.header.packet_number, 1);

    assert_eq!(
        server.receive(client_addr, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(12)
    );

    assert_eq!(&output[..12], b"hello server");

    let len = server.send_data(b"hello client", &mut packet)?;

    let decoded = decode_packet(&packet[..len])?;

    // Each direction has its own counter.
    assert_eq!(decoded.header.packet_number, 1);

    assert_eq!(
        client.receive(server_addr, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(12)
    );

    assert_eq!(&output[..12], b"hello client");

    Ok(())
}

#[test]
fn established_session_rejects_duplicate_data() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(b"LEStra", &mut packet)?;

    assert_eq!(
        server.receive(source, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(6)
    );

    output.fill(0xAA);

    assert!(matches!(
        server.receive(source, &packet[..len], &mut output,),
        Err(PacketProtectionError::ReplayRejected)
    ));

    assert_eq!(output, [0xAA; MAX_DATA_SIZE]);
    assert!(!server.is_closed());

    Ok(())
}

#[test]
fn session_supports_data_size_boundaries() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(&[], &mut packet)?;

    assert_eq!(
        server.receive(source, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(0)
    );

    let payload = [42_u8; MAX_DATA_SIZE];

    let len = client.send_data(&payload, &mut packet)?;

    assert_eq!(len, MAX_DATAGRAM_LEN);

    assert_eq!(
        server.receive(source, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(MAX_DATA_SIZE)
    );

    assert_eq!(output, payload);

    let oversized = [0_u8; MAX_DATA_SIZE + 1];

    assert!(matches!(
        client.send_data(&oversized, &mut packet),
        Err(PacketProtectionError::Codec(CodecError::Oversized))
    ));

    assert!(!client.is_closed());

    Ok(())
}

#[test]
fn authenticated_close_terminates_both_sessions() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut packet = [0_u8; CLOSE_SIZE];

    let len = client.send_close(&mut packet)?;

    assert_eq!(len, CLOSE_SIZE);
    assert!(client.is_closed());
    assert!(!server.is_closed());

    let decoded = decode_packet(&packet)?;

    assert_eq!(decoded.header.kind, PacketType::Close);
    assert_eq!(decoded.header.packet_number, 1);

    assert_eq!(
        server.receive(source, &packet, &mut [])?,
        ReceiveEvent::Closed
    );

    assert!(server.is_closed());

    let mut output = [0_u8; MAX_DATAGRAM_LEN];

    assert!(matches!(
        client.send_data(b"late data", &mut output),
        Err(PacketProtectionError::SessionClosed)
    ));

    assert!(matches!(
        server.send_data(b"late data", &mut output),
        Err(PacketProtectionError::SessionClosed)
    ));

    assert!(matches!(
        server.receive(source, &packet, &mut []),
        Err(PacketProtectionError::SessionClosed)
    ));

    assert!(matches!(
        client.send_close(&mut output),
        Err(PacketProtectionError::SessionClosed)
    ));

    Ok(())
}

#[test]
fn forged_close_does_not_terminate_session() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut close = [0_u8; CLOSE_SIZE];

    client.send_close(&mut close)?;

    let mut forged = close;

    *forged.last_mut().unwrap() ^= 1;

    assert!(matches!(
        server.receive(source, &forged, &mut []),
        Err(PacketProtectionError::Noise(_))
    ));

    assert!(!server.is_closed());

    let wrong_source = SocketAddr::from(([127, 0, 0, 1], 9999));

    assert!(matches!(
        server.receive(wrong_source, &close, &mut []),
        Err(PacketProtectionError::UnexpectedPeer)
    ));

    assert!(!server.is_closed());

    assert_eq!(
        server.receive(source, &close, &mut [])?,
        ReceiveEvent::Closed
    );

    assert!(server.is_closed());

    Ok(())
}

#[test]
fn insufficient_close_buffer_preserves_session() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut small = [0_u8; CLOSE_SIZE - 1];

    assert!(matches!(
        client.send_close(&mut small),
        Err(PacketProtectionError::Codec(
            CodecError::OutputTooSmall { .. }
        ))
    ));

    assert!(!client.is_closed());

    let mut packet = [0_u8; CLOSE_SIZE];

    client.send_close(&mut packet)?;

    assert_eq!(decode_packet(&packet)?.header.packet_number, 1);

    assert!(client.is_closed());

    assert_eq!(
        server.receive(source, &packet, &mut [])?,
        ReceiveEvent::Closed
    );

    Ok(())
}

#[test]
fn packets_cannot_cross_independent_sessions() -> TestResult {
    let (mut first_client, _) = established_pair()?;
    let (mut second_client, mut second_server) = established_pair()?;

    let source = second_server.remote_endpoint();

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0xAA_u8; MAX_DATA_SIZE];

    let len = first_client.send_data(b"first session", &mut packet)?;

    assert!(matches!(
        second_server.receive(source, &packet[..len], &mut output,),
        Err(PacketProtectionError::Noise(_))
    ));

    assert_eq!(output, [0xAA; MAX_DATA_SIZE]);
    assert!(!second_server.is_closed());

    let len = second_client.send_data(b"second session", &mut packet)?;

    assert_eq!(
        second_server.receive(source, &packet[..len], &mut output,)?,
        ReceiveEvent::Data(14)
    );

    assert_eq!(&output[..14], b"second session");

    Ok(())
}

#[test]
fn local_close_discards_handshake_recovery() -> TestResult {
    let (client, mut server) = pending_pair()?;

    let source = server.remote_endpoint();

    server.accept_confirm(source, client.confirm())?;

    let (mut server, ready) = server.into_established()?;

    assert_eq!(server.retry_ready(source, client.confirm()), Some(&ready));

    server.close_local();

    // Local closure is idempotent.
    server.close_local();

    assert!(server.is_closed());

    assert!(server.retry_ready(source, client.confirm()).is_none());

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];

    assert!(matches!(
        server.send_data(b"closed", &mut packet),
        Err(PacketProtectionError::SessionClosed)
    ));

    Ok(())
}

#[test]
fn authenticated_replay_window_enforces_exact_boundary() -> TestResult {
    let (mut client, mut server) = established_pair()?;

    let source = server.remote_endpoint();

    let mut oldest = [0_u8; MAX_DATAGRAM_LEN];
    let mut delayed = [0_u8; MAX_DATAGRAM_LEN];
    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut plaintext = [0_u8; MAX_DATA_SIZE];

    // Packet number 1.
    let oldest_len = client.send_data(b"expired", &mut oldest)?;

    // Packet number 2.
    let delayed_len = client.send_data(b"delayed", &mut delayed)?;

    // Generate packet numbers 3 through 1024.
    // Simulate loss by not delivering them.
    for _ in 3..1025 {
        client.send_data(b"lost", &mut packet)?;
    }

    // Packet number 1025.
    let len = client.send_data(b"latest", &mut packet)?;

    assert_eq!(decode_packet(&packet[..len])?.header.packet_number, 1025);

    assert_eq!(
        server.receive(source, &packet[..len], &mut plaintext,)?,
        ReceiveEvent::Data(6)
    );

    // Distance 1024: expired.
    plaintext.fill(0xAA);

    assert!(matches!(
        server.receive(source, &oldest[..oldest_len], &mut plaintext,),
        Err(PacketProtectionError::ReplayRejected)
    ));

    assert_eq!(plaintext, [0xAA; MAX_DATA_SIZE]);

    // Distance 1023: still within the window.
    assert_eq!(
        server.receive(source, &delayed[..delayed_len], &mut plaintext,)?,
        ReceiveEvent::Data(7)
    );

    assert_eq!(&plaintext[..7], b"delayed");

    // The accepted delayed packet cannot be replayed.
    assert!(matches!(
        server.receive(source, &delayed[..delayed_len], &mut plaintext,),
        Err(PacketProtectionError::ReplayRejected)
    ));

    assert!(!server.is_closed());

    Ok(())
}

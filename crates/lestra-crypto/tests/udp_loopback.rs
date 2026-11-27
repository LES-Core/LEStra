use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use lestra_codec::MAX_DATAGRAM_LEN;
use lestra_crypto::{
    CLOSE_SIZE, ClientStart, EstablishedSession, MAX_DATA_SIZE, PacketProtectionError,
    ReceiveEvent, ServerStart,
};
use snow::{Builder, Keypair, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn socket() -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;

    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    socket.set_write_timeout(Some(Duration::from_secs(3)))?;

    Ok(socket)
}

fn keys() -> Result<(Keypair, Keypair), snow::Error> {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    let builder = Builder::new(params);

    Ok((builder.generate_keypair()?, builder.generate_keypair()?))
}

fn transfer(
    sender: &UdpSocket,
    receiver: &UdpSocket,
    bytes: &[u8],
    output: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    let written = sender.send_to(bytes, receiver.local_addr()?)?;

    assert_eq!(written, bytes.len());

    let (len, source) = receiver.recv_from(output)?;

    assert_eq!(source, sender.local_addr()?);
    assert_eq!(len, bytes.len());
    assert_eq!(&output[..len], bytes);

    Ok((len, source))
}

fn establish(
    client_socket: &UdpSocket,
    server_socket: &UdpSocket,
    client_key: &Keypair,
    server_key: &Keypair,
) -> Result<(EstablishedSession, EstablishedSession), Box<dyn std::error::Error>> {
    let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;

    let client_public: [u8; 32] = client_key.public.as_slice().try_into()?;

    let server_private: [u8; 32] = server_key.private.as_slice().try_into()?;

    let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

    let server_addr = server_socket.local_addr()?;

    let mut wire = [0_u8; MAX_DATAGRAM_LEN + 1];

    // INITIAL
    let client = ClientStart::new(&client_private, &server_public, [1; 8], server_addr)?.start()?;

    let (len, source) = transfer(client_socket, server_socket, client.initial(), &mut wire)?;

    let server = ServerStart::new(&server_private, client_public, [2; 8])?
        .accept_initial(source, &wire[..len])?;

    // HANDSHAKE
    let (len, source) = transfer(server_socket, client_socket, server.response(), &mut wire)?;

    let mut client = client
        .accept_response(source, &wire[..len])?
        .start_confirmation()?;

    let mut server = server.await_confirmation()?;

    // CONFIRM
    let (len, source) = transfer(client_socket, server_socket, client.confirm(), &mut wire)?;

    server.accept_confirm(source, &wire[..len])?;

    let (mut server, ready) = server.into_established()?;

    // Simulate a lost READY by intentionally not sending it.
    // The client retransmits its original CONFIRM.
    let (len, source) = transfer(client_socket, server_socket, client.confirm(), &mut wire)?;

    let retried_ready = *server
        .retry_ready(source, &wire[..len])
        .expect("authenticated duplicate CONFIRM");

    assert_eq!(retried_ready, ready);

    // READY
    let (len, source) = transfer(server_socket, client_socket, &retried_ready, &mut wire)?;

    client.accept_ready(source, &wire[..len])?;

    Ok((client.into_established()?, server))
}

#[test]
fn secure_session_over_real_udp_sockets() -> TestResult {
    let client_socket = socket()?;
    let server_socket = socket()?;
    let attacker_socket = socket()?;

    let (client_key, server_key) = keys()?;

    let (mut client, mut server) =
        establish(&client_socket, &server_socket, &client_key, &server_key)?;

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut wire = [0_u8; MAX_DATAGRAM_LEN + 1];
    let mut plaintext = [0_u8; MAX_DATA_SIZE];

    // Client -> Server
    let len = client.send_data(b"hello server", &mut packet)?;

    let (len, source) = transfer(&client_socket, &server_socket, &packet[..len], &mut wire)?;

    assert_eq!(
        server.receive(source, &wire[..len], &mut plaintext,)?,
        ReceiveEvent::Data(12)
    );

    assert_eq!(&plaintext[..12], b"hello server");

    // Duplicate DATA must not be delivered again.
    plaintext.fill(0xAA);

    assert!(matches!(
        server.receive(source, &wire[..len], &mut plaintext,),
        Err(PacketProtectionError::ReplayRejected)
    ));

    assert_eq!(plaintext, [0xAA; MAX_DATA_SIZE]);

    // Server -> Client
    let len = server.send_data(b"hello client", &mut packet)?;

    let (len, source) = transfer(&server_socket, &client_socket, &packet[..len], &mut wire)?;

    assert_eq!(
        client.receive(source, &wire[..len], &mut plaintext,)?,
        ReceiveEvent::Data(12)
    );

    assert_eq!(&plaintext[..12], b"hello client");

    // Authenticated CLOSE.
    let mut close = [0_u8; CLOSE_SIZE];

    client.send_close(&mut close)?;

    assert!(client.is_closed());

    // Reject a genuine packet from a different UDP endpoint.
    let (len, source) = transfer(&attacker_socket, &server_socket, &close, &mut wire)?;

    assert!(matches!(
        server.receive(source, &wire[..len], &mut []),
        Err(PacketProtectionError::UnexpectedPeer)
    ));

    assert!(!server.is_closed());

    // Reject modified authentication tag.
    let mut forged = close;

    forged[CLOSE_SIZE - 1] ^= 1;

    let (len, source) = transfer(&client_socket, &server_socket, &forged, &mut wire)?;

    assert!(matches!(
        server.receive(source, &wire[..len], &mut []),
        Err(PacketProtectionError::Noise(_))
    ));

    assert!(!server.is_closed());

    // Accept the original authenticated CLOSE.
    let (len, source) = transfer(&client_socket, &server_socket, &close, &mut wire)?;

    assert_eq!(
        server.receive(source, &wire[..len], &mut [])?,
        ReceiveEvent::Closed
    );

    assert!(server.is_closed());

    Ok(())
}

#[test]
fn reconnect_rejects_packets_from_previous_session() -> TestResult {
    let client_socket = socket()?;
    let server_socket = socket()?;

    let (client_key, server_key) = keys()?;

    let (mut old_client, mut old_server) =
        establish(&client_socket, &server_socket, &client_key, &server_key)?;

    let mut old_packet = [0_u8; MAX_DATAGRAM_LEN];

    let old_len = old_client.send_data(b"old session", &mut old_packet)?;

    old_client.close_local();
    old_server.close_local();

    // Deliberately reuse static identities, endpoints and
    // test CIDs. Fresh Noise ephemeral keys must isolate
    // the new cryptographic session.
    let (mut client, mut server) =
        establish(&client_socket, &server_socket, &client_key, &server_key)?;

    let mut wire = [0_u8; MAX_DATAGRAM_LEN + 1];
    let mut plaintext = [0xAA_u8; MAX_DATA_SIZE];

    let (len, source) = transfer(
        &client_socket,
        &server_socket,
        &old_packet[..old_len],
        &mut wire,
    )?;

    assert!(matches!(
        server.receive(source, &wire[..len], &mut plaintext,),
        Err(PacketProtectionError::Noise(_))
    ));

    assert_eq!(plaintext, [0xAA; MAX_DATA_SIZE]);
    assert!(!server.is_closed());

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];

    let len = client.send_data(b"new session", &mut packet)?;

    let (len, source) = transfer(&client_socket, &server_socket, &packet[..len], &mut wire)?;

    assert_eq!(
        server.receive(source, &wire[..len], &mut plaintext,)?,
        ReceiveEvent::Data(11)
    );

    assert_eq!(&plaintext[..11], b"new session");

    Ok(())
}

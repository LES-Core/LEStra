use std::{
    io,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use lestra_codec::MAX_DATAGRAM_LEN;

use lestra_crypto::{ClientStart, EstablishedSession, MAX_DATA_SIZE, RESPONSE_SIZE, ReceiveEvent};

use lestra_transport_udp::{
    ConnectStatus, ConnectionId, ServerConfig, ServerEvent, UdpClient, UdpIo, UdpServer,
};

use snow::{Builder, Keypair, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn keys() -> Result<(Keypair, Keypair), snow::Error> {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    let builder = Builder::new(params);

    Ok((builder.generate_keypair()?, builder.generate_keypair()?))
}

fn key32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32-byte test key")
}

fn establish(
    server: &mut UdpServer<'_>,
    client_key: &Keypair,
    server_key: &Keypair,
    local_cid: ConnectionId,
) -> Result<(UdpIo, EstablishedSession), Box<dyn std::error::Error>> {
    let mut client = UdpClient::connect(
        UdpIo::bind(address())?,
        server.local_addr()?,
        &key32(&client_key.private),
        &key32(&server_key.public),
        local_cid,
    )?;

    let deadline = Instant::now() + Duration::from_secs(3);

    let mut output = [0_u8; MAX_DATA_SIZE];

    loop {
        let status = client.poll()?;

        server.poll(&mut output)?;

        if status == ConnectStatus::Established {
            return Ok(client.into_established()?);
        }

        if Instant::now() >= deadline {
            return Err(
                io::Error::new(io::ErrorKind::TimedOut, "client connection timeout").into(),
            );
        }

        thread::sleep(Duration::from_millis(1));
    }
}

fn poll_event(
    server: &mut UdpServer<'_>,
    output: &mut [u8; MAX_DATA_SIZE],
) -> io::Result<ServerEvent> {
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        let event = server.poll(output)?;

        if event != ServerEvent::Idle {
            return Ok(event);
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server event timeout",
            ));
        }

        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn client_and_server_establish_and_exchange_data() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let (io, mut client) = establish(&mut server, &client_key, &server_key, [1; 8])?;

    assert_eq!(server.pending_len(), 0);
    assert_eq!(server.established_len(), 1);

    let cid = client.remote_receive_cid();

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(b"hello server", &mut packet)?;

    io.send_to(server.local_addr()?, &packet[..len])?;

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Data { cid, len: 12 }
    );

    assert_eq!(&output[..12], b"hello server");

    server.send_data(cid, b"hello client")?;

    let mut io = io;

    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        if let Some(lestra_transport_udp::IncomingDatagram::Packet { source, bytes, .. }) =
            io.poll_recv()?
        {
            assert_eq!(
                client.receive(source, bytes, &mut output,)?,
                ReceiveEvent::Data(12)
            );

            assert_eq!(&output[..12], b"hello client");

            break;
        }

        assert!(Instant::now() < deadline, "client receive timeout");

        thread::sleep(Duration::from_millis(1));
    }

    let len = client.send_close(&mut packet)?;

    io.send_to(server.local_addr()?, &packet[..len])?;

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Closed { cid }
    );

    assert_eq!(server.established_len(), 0);

    Ok(())
}

#[test]
fn server_supports_multiple_independent_sessions() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let (first_io, mut first) = establish(&mut server, &client_key, &server_key, [1; 8])?;

    let (second_io, mut second) = establish(&mut server, &client_key, &server_key, [2; 8])?;

    assert_eq!(server.established_len(), 2);

    let first_cid = first.remote_receive_cid();
    let second_cid = second.remote_receive_cid();

    assert_ne!(first_cid, second_cid);
    assert_ne!(first_cid, [0; 8]);
    assert_ne!(second_cid, [0; 8]);

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = first.send_data(b"first", &mut packet)?;

    first_io.send_to(server.local_addr()?, &packet[..len])?;

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Data {
            cid: first_cid,
            len: 5,
        }
    );

    assert_eq!(&output[..5], b"first");

    let len = second.send_data(b"second", &mut packet)?;

    second_io.send_to(server.local_addr()?, &packet[..len])?;

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Data {
            cid: second_cid,
            len: 6,
        }
    );

    assert_eq!(&output[..6], b"second");

    assert!(server.disconnect(first_cid));
    assert_eq!(server.established_len(), 1);

    Ok(())
}

#[test]
fn repeated_initial_reuses_cached_handshake() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let sender = UdpSocket::bind(address())?;
    let other = UdpSocket::bind(address())?;

    sender.set_read_timeout(Some(Duration::from_secs(3)))?;

    let destination = server.local_addr()?;

    let client = ClientStart::new(
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        destination,
    )?
    .start()?;

    let initial = client.initial();

    let mut output = [0_u8; MAX_DATA_SIZE];
    let mut first = [0_u8; MAX_DATAGRAM_LEN];

    sender.send_to(initial, destination)?;

    assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Progress);

    let (len, _) = sender.recv_from(&mut first)?;

    assert_eq!(len, RESPONSE_SIZE);
    assert_eq!(server.pending_len(), 1);

    // A replay from another endpoint cannot
    // trigger a reflected HANDSHAKE.
    other.send_to(initial, destination)?;

    assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Ignored);

    // A modified INITIAL with the same ephemeral key
    // cannot replace the original cached record.
    let mut modified = *initial;
    *modified.last_mut().unwrap() ^= 1;

    sender.send_to(&modified, destination)?;

    assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Ignored);

    // Only five additional transmissions are allowed.
    for _ in 0..5 {
        sender.send_to(initial, destination)?;

        assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Progress);

        let mut repeated = [0_u8; MAX_DATAGRAM_LEN];

        let (len, _) = sender.recv_from(&mut repeated)?;

        assert_eq!(len, RESPONSE_SIZE);

        assert_eq!(&repeated[..len], &first[..len]);
    }

    sender.send_to(initial, destination)?;

    assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Ignored);

    assert_eq!(server.pending_len(), 1);
    assert_eq!(server.established_len(), 0);

    Ok(())
}

#[test]
fn unauthorized_client_does_not_allocate_session() -> TestResult {
    let (allowed, server_key) = keys()?;
    let (unauthorized, _) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&allowed.public),
    );

    let sender = UdpSocket::bind(address())?;
    let destination = server.local_addr()?;

    let client = ClientStart::new(
        &key32(&unauthorized.private),
        &key32(&server_key.public),
        [1; 8],
        destination,
    )?
    .start()?;

    sender.send_to(client.initial(), destination)?;

    let mut output = [0_u8; MAX_DATA_SIZE];

    assert_eq!(poll_event(&mut server, &mut output)?, ServerEvent::Ignored);

    assert_eq!(server.pending_len(), 0);
    assert_eq!(server.established_len(), 0);

    Ok(())
}

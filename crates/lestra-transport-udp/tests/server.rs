use std::{
    io,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use lestra_codec::{MAX_DATAGRAM_LEN, decode_packet};

use lestra_crypto::{ClientStart, EstablishedSession, MAX_DATA_SIZE, RESPONSE_SIZE, ReceiveEvent};

use lestra_transport_udp::{
    ClientConfig, ConnectError, ConnectStatus, ConnectionCloseReason, ConnectionEvent, ConnectionId, DataPacingConfig, ExpirationReason, FlushStatus, IncomingDatagram, PacingLimit, ServerConfig, ServerEvent, SessionTimeouts, UdpClient, UdpConnection, UdpIo, UdpServer,
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

fn establish_managed(
    server: &mut UdpServer<'_>,
    client_key: &Keypair,
    server_key: &Keypair,
    config: ClientConfig,
) -> Result<UdpConnection, Box<dyn std::error::Error>> {
    let mut client = UdpClient::connect(
        UdpIo::bind(address())?,
        server.local_addr()?,
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
    )?;

    let deadline = Instant::now() + Duration::from_secs(3);

    let mut output = [0_u8; MAX_DATA_SIZE];

    loop {
        let status = client.poll()?;

        server.poll(&mut output)?;

        if status == ConnectStatus::Established {
            return Ok(client.into_connection(config)?);
        }

        if Instant::now() >= deadline {
            return Err(
                io::Error::new(io::ErrorKind::TimedOut, "managed connection timeout").into(),
            );
        }

        thread::sleep(Duration::from_millis(1));
    }
}

fn poll_connection(
    connection: &mut UdpConnection,
    output: &mut [u8; MAX_DATA_SIZE],
) -> io::Result<ConnectionEvent> {
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        let event = connection.poll(output)?;

        if event != ConnectionEvent::Idle {
            return Ok(event);
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection event timeout",
            ));
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

#[test]
fn server_reports_session_expiration_without_network_input() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let config = ServerConfig {
        timeouts: SessionTimeouts {
            idle_timeout: Duration::ZERO,
            max_lifetime: Duration::from_secs(60),
        },
        ..ServerConfig::default()
    };

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        config,
        &server_private,
        key32(&client_key.public),
    );

    let mut client = UdpClient::connect(
        UdpIo::bind(address())?,
        server.local_addr()?,
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
    )?;

    let deadline = Instant::now() + Duration::from_secs(3);

    let mut output = [0_u8; MAX_DATA_SIZE];

    let cid = loop {
        client.poll()?;

        if let ServerEvent::Established { cid, .. } = server.poll(&mut output)? {
            break cid;
        }

        assert!(Instant::now() < deadline, "server establishment timeout");

        thread::sleep(Duration::from_millis(1));
    };

    assert_eq!(server.established_len(), 1);

    // No new datagram is needed to trigger expiration.
    assert_eq!(
        server.poll(&mut output)?,
        ServerEvent::Expired {
            cid,
            reason: ExpirationReason::IdleTimeout,
        }
    );

    assert_eq!(server.established_len(), 0);

    Ok(())
}

#[test]
fn pacing_rejection_does_not_consume_packet_number() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let config = ServerConfig {
        pacing: DataPacingConfig {
            per_session: PacingLimit {
                bytes_per_second: 0,
                burst_bytes: 48,
            },

            global: PacingLimit {
                bytes_per_second: 0,
                burst_bytes: 1200,
            },
        },

        ..ServerConfig::default()
    };

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        config,
        &server_private,
        key32(&client_key.public),
    );

    let (mut io, mut client) = establish(&mut server, &client_key, &server_key, [1; 8])?;

    let cid = client.remote_receive_cid();

    // 7 payload bytes + 42 overhead = 49 bytes.
    // The per-session burst permits only 48 bytes.
    let error = server
        .send_data(cid, b"blocked")
        .expect_err("pacing limit must reject packet");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    // 6 payload bytes + 42 overhead = 48 bytes.
    server.send_data(cid, b"LEStra")?;

    let error = server
        .send_data(cid, b"")
        .expect_err("session budget is exhausted");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    let deadline = Instant::now() + Duration::from_secs(3);

    let mut output = [0_u8; MAX_DATA_SIZE];

    loop {
        if let Some(IncomingDatagram::Packet { source, bytes, .. }) = io.poll_recv()? {
            let packet = decode_packet(bytes)?;

            // The rejected transmission must not
            // have consumed packet number 1.
            assert_eq!(packet.header.packet_number, 1);

            assert_eq!(
                client.receive(source, bytes, &mut output,)?,
                ReceiveEvent::Data(6)
            );

            assert_eq!(&output[..6], b"LEStra");

            break;
        }

        assert!(Instant::now() < deadline, "DATA receive timeout");

        thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(server.established_len(), 1);

    // CLOSE is not blocked by the DATA budget.
    server.send_close(cid)?;

    assert_eq!(server.established_len(), 0);

    Ok(())
}

#[test]
fn global_pacing_limits_combined_session_traffic() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let config = ServerConfig {
        pacing: DataPacingConfig {
            per_session: PacingLimit {
                bytes_per_second: 0,
                burst_bytes: 1200,
            },

            global: PacingLimit {
                bytes_per_second: 0,
                burst_bytes: 48,
            },
        },

        ..ServerConfig::default()
    };

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        config,
        &server_private,
        key32(&client_key.public),
    );

    let (_first_io, first) = establish(&mut server, &client_key, &server_key, [1; 8])?;

    let (_second_io, second) = establish(&mut server, &client_key, &server_key, [2; 8])?;

    let first_cid = first.remote_receive_cid();
    let second_cid = second.remote_receive_cid();

    server.send_data(first_cid, b"LEStra")?;

    let error = server
        .send_data(second_cid, b"LEStra")
        .expect_err("global budget is exhausted");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    assert_eq!(server.established_len(), 2);

    Ok(())
}

#[test]
fn managed_connection_exchanges_data() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let mut client = establish_managed(
        &mut server,
        &client_key,
        &server_key,
        ClientConfig::default(),
    )?;

    assert!(!client.has_pending_data());
    assert!(!server.has_pending_data());

    assert_eq!(client.poll_send()?, FlushStatus::Idle);

    assert_eq!(server.poll_send()?, FlushStatus::Idle);

    let cid = client.remote_receive_cid();

    assert!(!client.is_closed());

    client.send_data(b"hello server")?;

    let mut output = [0_u8; MAX_DATA_SIZE];

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Data { cid, len: 12 }
    );

    assert_eq!(&output[..12], b"hello server");

    server.send_data(cid, b"hello client")?;

    assert_eq!(
        poll_connection(&mut client, &mut output)?,
        ConnectionEvent::Data { len: 12 }
    );

    assert_eq!(&output[..12], b"hello client");

    client.send_close()?;

    assert!(client.is_closed());

    assert_eq!(client.close_reason(), Some(ConnectionCloseReason::Local));

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Closed { cid }
    );

    assert_eq!(server.established_len(), 0);

    let error = client
        .send_data(b"closed")
        .expect_err("closed connection cannot send");

    assert_eq!(error.kind(), io::ErrorKind::NotConnected);

    Ok(())
}

#[test]
fn managed_connection_enforces_pacing() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let config = ClientConfig {
        pacing: PacingLimit {
            bytes_per_second: 0,
            burst_bytes: 48,
        },

        ..ClientConfig::default()
    };

    let mut client = establish_managed(&mut server, &client_key, &server_key, config)?;

    let cid = client.remote_receive_cid();

    // 49 wire bytes exceed the available burst.
    let error = client
        .send_data(b"blocked")
        .expect_err("pacing must reject oversized burst");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    // Exactly 48 wire bytes.
    client.send_data(b"LEStra")?;

    let mut output = [0_u8; MAX_DATA_SIZE];

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Data { cid, len: 6 }
    );

    assert_eq!(&output[..6], b"LEStra");

    let error = client
        .send_data(b"")
        .expect_err("pacing budget is exhausted");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    assert!(!client.is_closed());

    // CLOSE must bypass the DATA budget.
    client.send_close()?;

    assert!(client.is_closed());

    assert_eq!(
        poll_event(&mut server, &mut output)?,
        ServerEvent::Closed { cid }
    );

    Ok(())
}

#[test]
fn managed_connection_accepts_remote_close() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let mut client = establish_managed(
        &mut server,
        &client_key,
        &server_key,
        ClientConfig::default(),
    )?;

    server.send_close(client.remote_receive_cid())?;

    let mut output = [0xAA_u8; MAX_DATA_SIZE];

    let expected = ConnectionEvent::Closed {
        reason: ConnectionCloseReason::Remote,
    };

    assert_eq!(poll_connection(&mut client, &mut output)?, expected);

    assert!(client.is_closed());

    assert_eq!(client.close_reason(), Some(ConnectionCloseReason::Remote));

    assert_eq!(output, [0xAA; MAX_DATA_SIZE]);

    // Repeated closure cannot replace the original reason.
    client.close_local();

    assert_eq!(client.poll(&mut output)?, expected);

    Ok(())
}

#[test]
fn managed_connection_expires_without_network_input() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server_private = key32(&server_key.private);

    let mut server = UdpServer::new(
        UdpIo::bind(address())?,
        ServerConfig::default(),
        &server_private,
        key32(&client_key.public),
    );

    let config = ClientConfig {
        timeouts: SessionTimeouts {
            idle_timeout: Duration::ZERO,
            max_lifetime: Duration::from_secs(60),
        },

        ..ClientConfig::default()
    };

    let mut client = establish_managed(&mut server, &client_key, &server_key, config)?;

    let mut output = [0xAA_u8; MAX_DATA_SIZE];

    let error = client
        .send_data(b"expired")
        .expect_err("expired connection cannot send");

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);

    assert_eq!(
        client.poll(&mut output)?,
        ConnectionEvent::Closed {
            reason: ConnectionCloseReason::Expired(ExpirationReason::IdleTimeout,),
        }
    );

    assert!(client.is_closed());
    assert_eq!(output, [0xAA; MAX_DATA_SIZE]);

    Ok(())
}

#[test]
fn managed_connection_requires_authenticated_ready() -> TestResult {
    let (client_key, server_key) = keys()?;

    let server = UdpSocket::bind(address())?;

    let client = UdpClient::connect(
        UdpIo::bind(address())?,
        server.local_addr()?,
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
    )?;

    assert!(matches!(
        client.into_connection(ClientConfig::default()),
        Err(ConnectError::NotEstablished)
    ));

    Ok(())
}

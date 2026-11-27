use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use lestra_codec::MAX_DATAGRAM_LEN;

use lestra_crypto::{
    CLOSE_SIZE, ClientAwaitingReady, ClientStart, EstablishedSession, MAX_DATA_SIZE,
    PacketProtectionError, ReceiveEvent, ServerAwaitingConfirm, ServerStart,
};

use lestra_transport_udp::{
    ConnectionId, ExpirationReason, RouteEvent, SessionTable, SessionTableError, SessionTimeouts,
};

use snow::{Builder, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn pending_pair(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    client_addr: SocketAddr,
) -> Result<(ClientAwaitingReady, ServerAwaitingConfirm), Box<dyn std::error::Error>> {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    let builder = Builder::new(params);

    let client_key = builder.generate_keypair()?;
    let server_key = builder.generate_keypair()?;

    let client_private: [u8; 32] = client_key.private.as_slice().try_into()?;

    let client_public: [u8; 32] = client_key.public.as_slice().try_into()?;

    let server_private: [u8; 32] = server_key.private.as_slice().try_into()?;

    let server_public: [u8; 32] = server_key.public.as_slice().try_into()?;

    let client =
        ClientStart::new(&client_private, &server_public, client_cid, addr(5000))?.start()?;

    let server = ServerStart::new(&server_private, client_public, server_cid)?
        .accept_initial(client_addr, client.initial())?;

    let client = client
        .accept_response(addr(5000), server.response())?
        .start_confirmation()?;

    let server = server.await_confirmation()?;

    Ok((client, server))
}

fn establish(
    table: &mut SessionTable,
    now: Instant,
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    client_addr: SocketAddr,
) -> Result<EstablishedSession, Box<dyn std::error::Error>> {
    let (mut client, server) = pending_pair(client_cid, server_cid, client_addr)?;

    table.insert_pending(server, now)?;

    let RouteEvent::Established {
        cid,
        destination,
        ready,
    } = table.route(now, client_addr, client.confirm(), &mut [])?
    else {
        panic!("session must be established");
    };

    assert_eq!(cid, server_cid);
    assert_eq!(destination, client_addr);

    client.accept_ready(addr(5000), &ready)?;

    Ok(client.into_established()?)
}

#[test]
fn session_table_enforces_capacity() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::new(2, 1);

    assert!(table.is_empty());
    assert!(table.has_pending_capacity());

    let (_, server) = pending_pair([1; 8], [2; 8], addr(4000))?;

    table.insert_pending(server, now)?;

    assert_eq!(table.pending_len(), 1);
    assert!(!table.has_pending_capacity());

    let (_, server) = pending_pair([3; 8], [4; 8], addr(4001))?;

    assert!(matches!(
        table.insert_pending(server, now),
        Err(SessionTableError::PendingCapacityExceeded)
    ));

    assert!(table.remove([2; 8]));
    assert!(table.is_empty());

    let _client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let (_, server) = pending_pair([3; 8], [4; 8], addr(4001))?;

    table.insert_pending(server, now)?;

    assert_eq!(table.len(), 2);

    let (_, server) = pending_pair([5; 8], [6; 8], addr(4002))?;

    assert!(matches!(
        table.insert_pending(server, now),
        Err(SessionTableError::CapacityExceeded)
    ));

    assert_eq!(table.established_len(), 1);
    assert_eq!(table.pending_len(), 1);

    Ok(())
}

#[test]
fn cid_collision_cannot_replace_live_session() -> TestResult {
    let now = Instant::now();
    let mut table = SessionTable::new(10, 5);

    let mut client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let (_, collision) = pending_pair([3; 8], [2; 8], addr(4001))?;

    assert!(matches!(
        table.insert_pending(collision, now),
        Err(SessionTableError::ConnectionIdCollision)
    ));

    assert_eq!(table.established_len(), 1);
    assert_eq!(table.pending_len(), 0);

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut plaintext = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(b"original session", &mut packet)?;

    assert_eq!(
        table.route(now, addr(4000), &packet[..len], &mut plaintext,)?,
        RouteEvent::Data {
            cid: [2; 8],
            len: 16,
        }
    );

    assert_eq!(&plaintext[..16], b"original session");

    Ok(())
}

#[test]
fn routes_multiple_independent_clients() -> TestResult {
    let now = Instant::now();
    let mut table = SessionTable::new(10, 5);

    let mut first = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut second = establish(&mut table, now, [3; 8], [4; 8], addr(4001))?;

    assert_eq!(table.established_len(), 2);

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut plaintext = [0_u8; MAX_DATA_SIZE];

    let len = first.send_data(b"first", &mut packet)?;

    assert_eq!(
        table.route(now, addr(4000), &packet[..len], &mut plaintext,)?,
        RouteEvent::Data {
            cid: [2; 8],
            len: 5,
        }
    );

    assert_eq!(&plaintext[..5], b"first");

    let len = second.send_data(b"second", &mut packet)?;

    assert_eq!(
        table.route(now, addr(4001), &packet[..len], &mut plaintext,)?,
        RouteEvent::Data {
            cid: [4; 8],
            len: 6,
        }
    );

    assert_eq!(&plaintext[..6], b"second");

    let (destination, len) = table.send_data([4; 8], b"response", &mut packet)?;

    assert_eq!(destination, addr(4001));

    assert_eq!(
        second.receive(addr(5000), &packet[..len], &mut plaintext,)?,
        ReceiveEvent::Data(8)
    );

    assert_eq!(&plaintext[..8], b"response");

    Ok(())
}

#[test]
fn promotion_and_ready_retry_are_idempotent() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::new(10, 5);

    let (mut client, server) = pending_pair([1; 8], [2; 8], addr(4000))?;

    table.insert_pending(server, now)?;

    let confirm = *client.confirm();

    assert_eq!(
        table.route(now, addr(9999), &confirm, &mut [],)?,
        RouteEvent::Ignored
    );

    assert_eq!(table.pending_len(), 1);

    let mut forged = confirm;
    *forged.last_mut().unwrap() ^= 1;

    assert!(matches!(
        table.route(now, addr(4000), &forged, &mut [],),
        Err(SessionTableError::Protection(PacketProtectionError::Noise(
            _
        )))
    ));

    assert_eq!(table.pending_len(), 1);

    let RouteEvent::Established { ready, .. } = table.route(now, addr(4000), &confirm, &mut [])?
    else {
        panic!("expected established session");
    };

    assert_eq!(table.pending_len(), 0);
    assert_eq!(table.established_len(), 1);

    assert_eq!(
        table.route(now, addr(4000), &confirm, &mut [],)?,
        RouteEvent::RetryReady {
            cid: [2; 8],
            destination: addr(4000),
            ready,
        }
    );

    assert_eq!(table.established_len(), 1);

    client.accept_ready(addr(5000), &ready)?;

    assert!(client.into_established().is_ok());

    Ok(())
}

#[test]
fn handshake_expiry_preserves_established_sessions() -> TestResult {
    let now = Instant::now();
    let mut table = SessionTable::new(10, 5);

    let (client, server) = pending_pair([1; 8], [2; 8], addr(4000))?;

    table.insert_pending(server, now)?;

    let confirm = *client.confirm();

    let _client = establish(&mut table, now, [3; 8], [4; 8], addr(4001))?;

    let expired = now + Duration::from_secs(15);

    assert_eq!(table.expire_handshakes(expired), 1);

    assert_eq!(table.pending_len(), 0);
    assert_eq!(table.established_len(), 1);

    assert_eq!(
        table.route(expired, addr(4000), &confirm, &mut [],)?,
        RouteEvent::Ignored
    );

    assert!(!table.contains([2; 8]));
    assert!(table.contains([4; 8]));

    Ok(())
}

#[test]
fn authenticated_close_removes_session() -> TestResult {
    let now = Instant::now();
    let mut table = SessionTable::new(10, 5);

    let mut client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut packet = [0_u8; CLOSE_SIZE];

    client.send_close(&mut packet)?;

    let mut forged = packet;
    forged[CLOSE_SIZE - 1] ^= 1;

    assert!(matches!(
        table.route(now, addr(4000), &forged, &mut [],),
        Err(SessionTableError::Protection(PacketProtectionError::Noise(
            _
        )))
    ));

    assert_eq!(table.established_len(), 1);

    assert_eq!(
        table.route(now, addr(4000), &packet, &mut [],)?,
        RouteEvent::Closed { cid: [2; 8] }
    );

    assert!(table.is_empty());

    assert_eq!(
        table.route(now, addr(4000), &packet, &mut [],)?,
        RouteEvent::Ignored
    );

    Ok(())
}

#[test]
fn server_close_retires_session() -> TestResult {
    let now = Instant::now();
    let mut table = SessionTable::new(10, 5);

    let mut client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut packet = [0_u8; CLOSE_SIZE];

    let (destination, len) = table.send_close([2; 8], &mut packet)?;

    assert_eq!(destination, addr(4000));
    assert_eq!(len, CLOSE_SIZE);

    assert!(table.is_empty());

    assert_eq!(
        client.receive(addr(5000), &packet[..len], &mut [],)?,
        ReceiveEvent::Closed
    );

    assert!(client.is_closed());

    assert!(matches!(
        table.send_data([2; 8], b"closed", &mut packet,),
        Err(SessionTableError::UnknownConnection)
    ));

    Ok(())
}

#[test]
fn pending_capacity_is_limited_per_ip() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::new(10, 5);

    let (_, first) = pending_pair([1; 8], [2; 8], addr(4000))?;

    let (_, second) = pending_pair([3; 8], [4; 8], addr(4001))?;

    table.insert_pending(first, now)?;
    table.insert_pending(second, now)?;

    let ip = addr(4000).ip();

    assert_eq!(table.pending_for_ip(ip), 2);

    assert!(table.has_pending_capacity());

    assert!(!table.has_pending_capacity_for_ip(ip, 2,));

    let other_ip = SocketAddr::from(([127, 0, 0, 2], 4000)).ip();

    assert!(table.has_pending_capacity_for_ip(other_ip, 2,));

    assert!(table.remove([2; 8]));

    assert_eq!(table.pending_for_ip(ip), 1);

    assert!(table.has_pending_capacity_for_ip(ip, 2,));

    Ok(())
}

#[test]
fn idle_session_expires_at_exact_boundary() -> TestResult {
    let now = Instant::now();

    let timeouts = SessionTimeouts {
        idle_timeout: Duration::from_secs(5),
        max_lifetime: Duration::from_secs(60),
    };

    let mut table = SessionTable::with_timeouts(10, 5, timeouts);

    let _client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    assert_eq!(table.pop_expired(now + Duration::from_millis(4999)), None);

    assert_eq!(
        table.pop_expired(now + Duration::from_secs(5)),
        Some(([2; 8], ExpirationReason::IdleTimeout,))
    );

    assert!(table.is_empty());

    assert_eq!(table.pop_expired(now + Duration::from_secs(60)), None);

    Ok(())
}

#[test]
fn only_authenticated_fresh_data_refreshes_idle_timeout() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::with_timeouts(
        10,
        5,
        SessionTimeouts {
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(60),
        },
    );

    let mut client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    let len = client.send_data(b"active", &mut packet)?;

    // Refresh activity at t = 4 seconds.
    assert_eq!(
        table.route(
            now + Duration::from_secs(4),
            addr(4000),
            &packet[..len],
            &mut output,
        )?,
        RouteEvent::Data {
            cid: [2; 8],
            len: 6,
        }
    );

    let later = now + Duration::from_secs(8);

    assert_eq!(table.pop_expired(later), None);

    // Replayed DATA cannot refresh the idle timeout.
    assert!(matches!(
        table.route(later, addr(4000), &packet[..len], &mut output,),
        Err(SessionTableError::Protection(
            PacketProtectionError::ReplayRejected
        ))
    ));

    // Fresh packet number with an invalid AEAD tag.
    let len = client.send_data(b"forged", &mut packet)?;

    packet[len - 1] ^= 1;

    assert!(matches!(
        table.route(later, addr(4000), &packet[..len], &mut output,),
        Err(SessionTableError::Protection(PacketProtectionError::Noise(
            _
        )))
    ));

    // Last authenticated activity remains at t = 4.
    assert_eq!(
        table.pop_expired(now + Duration::from_secs(9)),
        Some(([2; 8], ExpirationReason::IdleTimeout,))
    );

    assert!(table.is_empty());

    Ok(())
}

#[test]
fn maximum_lifetime_cannot_be_extended_by_data() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::with_timeouts(
        10,
        5,
        SessionTimeouts {
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(12),
        },
    );

    let mut client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATA_SIZE];

    for seconds in [4, 8, 11] {
        let len = client.send_data(b"active", &mut packet)?;

        assert_eq!(
            table.route(
                now + Duration::from_secs(seconds),
                addr(4000),
                &packet[..len],
                &mut output,
            )?,
            RouteEvent::Data {
                cid: [2; 8],
                len: 6,
            }
        );
    }

    assert_eq!(table.pop_expired(now + Duration::from_secs(11)), None);

    let len = client.send_data(b"expired", &mut packet)?;

    output.fill(0xAA);

    // Expiration is checked even before maintenance.
    assert_eq!(
        table.route(
            now + Duration::from_secs(12),
            addr(4000),
            &packet[..len],
            &mut output,
        )?,
        RouteEvent::Expired {
            cid: [2; 8],
            reason: ExpirationReason::MaxLifetime,
        }
    );

    assert_eq!(output, [0xAA; MAX_DATA_SIZE]);
    assert!(table.is_empty());

    Ok(())
}

#[test]
fn removed_session_does_not_leave_stale_timer_entries() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::with_timeouts(
        10,
        5,
        SessionTimeouts {
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(60),
        },
    );

    let _first = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    assert!(table.remove([2; 8]));

    // Reuse a test CID to detect stale timer indexes.
    let _second = establish(
        &mut table,
        now + Duration::from_secs(4),
        [3; 8],
        [2; 8],
        addr(4001),
    )?;

    assert_eq!(table.pop_expired(now + Duration::from_secs(5)), None);

    assert_eq!(table.established_len(), 1);

    assert_eq!(
        table.pop_expired(now + Duration::from_secs(9)),
        Some(([2; 8], ExpirationReason::IdleTimeout,))
    );

    assert!(table.is_empty());

    Ok(())
}

#[test]
fn expired_session_cannot_protect_outgoing_data() -> TestResult {
    let now = Instant::now();

    let mut table = SessionTable::with_timeouts(
        10,
        5,
        SessionTimeouts {
            idle_timeout: Duration::ZERO,
            max_lifetime: Duration::from_secs(60),
        },
    );

    let _client = establish(&mut table, now, [1; 8], [2; 8], addr(4000))?;

    let mut packet = [0xAA_u8; MAX_DATAGRAM_LEN];

    assert!(matches!(
        table.send_data([2; 8], b"expired", &mut packet,),
        Err(SessionTableError::SessionExpired)
    ));

    assert_eq!(packet, [0xAA; MAX_DATAGRAM_LEN]);

    assert_eq!(
        table.pop_expired(Instant::now()),
        Some(([2; 8], ExpirationReason::IdleTimeout,))
    );

    assert!(table.is_empty());

    Ok(())
}

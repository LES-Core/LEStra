use std::{
    io,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use lestra_codec::{
    AEAD_TAG_LEN, CodecError, HEADER_LEN, MAX_DATAGRAM_LEN, PacketHeader, PacketType,
    encode_packet_into,
};

use lestra_transport_udp::{IncomingDatagram, UdpIo};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn endpoint() -> io::Result<UdpIo> {
    UdpIo::bind(address())
}

fn data_header() -> PacketHeader {
    PacketHeader {
        kind: PacketType::Data,
        destination_connection_id: [1; 8],
        packet_number: 1,
    }
}

fn wait_for_datagram(
    receiver: &mut UdpIo,
    check: impl FnOnce(IncomingDatagram<'_>),
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        if let Some(packet) = receiver.poll_recv()? {
            check(packet);

            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "UDP receive timeout",
            ));
        }

        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn empty_socket_returns_none() -> TestResult {
    let mut socket = endpoint()?;

    assert!(socket.poll_recv()?.is_none());

    Ok(())
}

#[test]
fn transfers_valid_wire_datagram() -> TestResult {
    let sender = endpoint()?;
    let mut receiver = endpoint()?;

    let source = sender.local_addr()?;
    let destination = receiver.local_addr()?;

    let header = data_header();
    let body = [42_u8; AEAD_TAG_LEN + 8];

    let mut buffer = [0_u8; MAX_DATAGRAM_LEN];

    let packet = encode_packet_into(header, &body, &mut buffer)?;

    sender.send_to(destination, packet)?;

    wait_for_datagram(&mut receiver, |incoming| match incoming {
        IncomingDatagram::Packet {
            source: actual_source,
            header: actual_header,
            bytes,
        } => {
            assert_eq!(actual_source, source);
            assert_eq!(actual_header, header);
            assert_eq!(bytes, packet);
        }

        IncomingDatagram::Rejected { error, .. } => {
            panic!("unexpected rejection: {error}");
        }
    })?;

    Ok(())
}

#[test]
fn rejects_malformed_incoming_datagram() -> TestResult {
    let sender = UdpSocket::bind(address())?;
    let mut receiver = endpoint()?;

    let source = sender.local_addr()?;
    let destination = receiver.local_addr()?;

    sender.send_to(b"invalid", destination)?;

    wait_for_datagram(&mut receiver, |incoming| {
        assert!(matches!(
            incoming,
            IncomingDatagram::Rejected {
                source: actual_source,
                error: CodecError::Truncated,
            } if actual_source == source
        ));
    })?;

    Ok(())
}

#[test]
fn rejects_oversized_datagram_with_valid_prefix() -> TestResult {
    let sender = UdpSocket::bind(address())?;
    let mut receiver = endpoint()?;

    let destination = receiver.local_addr()?;

    let mut buffer = [0_u8; 4096];

    let body = [42_u8; MAX_DATAGRAM_LEN - HEADER_LEN];

    let packet = encode_packet_into(data_header(), &body, &mut buffer)?;

    assert_eq!(packet.len(), MAX_DATAGRAM_LEN);

    // The first 1200 bytes form a valid wire packet,
    // but the complete UDP datagram is oversized.
    sender.send_to(&buffer, destination)?;

    wait_for_datagram(&mut receiver, |incoming| {
        assert!(matches!(
            incoming,
            IncomingDatagram::Rejected {
                error: CodecError::Oversized,
                ..
            }
        ));
    })?;

    Ok(())
}

#[test]
fn accepts_maximum_datagram_size() -> TestResult {
    let sender = endpoint()?;
    let mut receiver = endpoint()?;

    let body = [42_u8; MAX_DATAGRAM_LEN - HEADER_LEN];

    let mut buffer = [0_u8; MAX_DATAGRAM_LEN];

    let packet = encode_packet_into(data_header(), &body, &mut buffer)?;

    assert_eq!(packet.len(), MAX_DATAGRAM_LEN);

    sender.send_to(receiver.local_addr()?, packet)?;

    wait_for_datagram(&mut receiver, |incoming| match incoming {
        IncomingDatagram::Packet { bytes, .. } => {
            assert_eq!(bytes.len(), MAX_DATAGRAM_LEN);

            assert_eq!(bytes, packet);
        }

        IncomingDatagram::Rejected { error, .. } => {
            panic!("unexpected rejection: {error}");
        }
    })?;

    Ok(())
}

#[test]
fn rejects_invalid_outgoing_datagram() -> TestResult {
    let sender = endpoint()?;
    let mut receiver = endpoint()?;

    let error = sender
        .send_to(receiver.local_addr()?, b"invalid")
        .expect_err("invalid framing must be rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    assert!(receiver.poll_recv()?.is_none());

    Ok(())
}

#[test]
fn malformed_packet_does_not_break_receiver() -> TestResult {
    let sender = UdpSocket::bind(address())?;
    let mut receiver = endpoint()?;

    let destination = receiver.local_addr()?;

    sender.send_to(b"invalid", destination)?;

    wait_for_datagram(&mut receiver, |incoming| {
        assert!(matches!(incoming, IncomingDatagram::Rejected { .. }));
    })?;

    let body = [0_u8; AEAD_TAG_LEN];
    let mut buffer = [0_u8; MAX_DATAGRAM_LEN];

    let packet = encode_packet_into(data_header(), &body, &mut buffer)?;

    sender.send_to(packet, destination)?;

    wait_for_datagram(&mut receiver, |incoming| {
        assert!(matches!(incoming, IncomingDatagram::Packet { .. }));
    })?;

    Ok(())
}

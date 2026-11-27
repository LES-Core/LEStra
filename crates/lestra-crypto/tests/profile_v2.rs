use std::net::SocketAddr;

use lestra_codec::{
    CodecError, MAX_DATAGRAM_LEN,
    v2::{self, ACK_BITMAP_LEN, ACK_PACKET_LEN, AckFrame, PacketType},
};

use lestra_crypto::{
    ClientAwaitingReady, ClientStart, EstablishedSession, HandshakeError, PacketProtectionError,
    ReceiveEvent, ServerAwaitingConfirm, ServerStart, WireProfile,
};

use snow::{Builder, Keypair, params::NoiseParams};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn keys() -> Result<(Keypair, Keypair), snow::Error> {
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;

    let builder = Builder::new(params);

    Ok((builder.generate_keypair()?, builder.generate_keypair()?))
}

fn key32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32-byte test key")
}

fn pending_pair(
    profile: WireProfile,
) -> Result<(ClientAwaitingReady, ServerAwaitingConfirm), Box<dyn std::error::Error>> {
    let (client_key, server_key) = keys()?;

    let client = ClientStart::new_with_profile(
        profile,
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;

    assert_eq!(client.initial()[4], profile.wire_major(),);

    let server = ServerStart::new_with_profile(
        profile,
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?
    .accept_initial(addr(4000), client.initial())?;

    assert_eq!(server.response()[4], profile.wire_major(),);

    let client = client.accept_response(addr(5000), server.response())?;

    assert_eq!(client.profile(), profile);

    assert_eq!(
        client.transcript_hash(),
        server.verified_noise().transcript_hash(),
    );

    Ok((client.start_confirmation()?, server.await_confirmation()?))
}

fn established_pair(
    profile: WireProfile,
) -> Result<(EstablishedSession, EstablishedSession), Box<dyn std::error::Error>> {
    let (mut client, mut server) = pending_pair(profile)?;

    server.accept_confirm(addr(4000), client.confirm())?;

    // Test-only simulated successful READY delivery.
    let ready = *server.ready().unwrap();

    client.accept_ready(addr(5000), &ready)?;

    let server = server.into_established_after_ready_sent()?;

    Ok((client.into_established()?, server))
}

fn ack_frame() -> AckFrame {
    let mut bitmap = [0_u8; ACK_BITMAP_LEN];

    bitmap[0] = 1;

    AckFrame::new(1, bitmap).unwrap()
}

#[test]
fn v2_handshake_establishes_both_peers() -> TestResult {
    let (client, server) = established_pair(WireProfile::V2)?;

    assert_eq!(client.profile(), WireProfile::V2);
    assert_eq!(server.profile(), WireProfile::V2);

    assert_eq!(client.local_receive_cid(), server.remote_receive_cid(),);

    assert_eq!(client.remote_receive_cid(), server.local_receive_cid(),);

    Ok(())
}

#[test]
fn cross_profile_initial_is_rejected() -> TestResult {
    let (client_key, server_key) = keys()?;

    for (client_profile, server_profile) in [
        (WireProfile::V1, WireProfile::V2),
        (WireProfile::V2, WireProfile::V1),
    ] {
        let client = ClientStart::new_with_profile(
            client_profile,
            &key32(&client_key.private),
            &key32(&server_key.public),
            [1; 8],
            addr(5000),
        )?
        .start()?;

        let server = ServerStart::new_with_profile(
            server_profile,
            &key32(&server_key.private),
            key32(&client_key.public),
            [2; 8],
        )?;

        assert!(matches!(
            server.accept_initial(addr(4000), client.initial(),),
            Err(HandshakeError::Codec(CodecError::UnsupportedVersion(_)))
        ));
    }

    Ok(())
}

#[test]
fn rewriting_wire_major_does_not_bypass_noise() -> TestResult {
    let (client_key, server_key) = keys()?;

    let client = ClientStart::new_with_profile(
        WireProfile::V1,
        &key32(&client_key.private),
        &key32(&server_key.public),
        [1; 8],
        addr(5000),
    )?
    .start()?;

    let mut modified = *client.initial();

    modified[4] = WireProfile::V2.wire_major();

    assert!(v2::decode_packet(&modified).is_ok());

    let server = ServerStart::new_with_profile(
        WireProfile::V2,
        &key32(&server_key.private),
        key32(&client_key.public),
        [2; 8],
    )?;

    assert!(matches!(
        server.accept_initial(addr(4000), &modified,),
        Err(HandshakeError::Noise(_))
    ));

    Ok(())
}

#[test]
fn v2_rejects_legacy_server_establishment() -> TestResult {
    let (client, mut server) = pending_pair(WireProfile::V2)?;

    assert!(server.ready().is_none());

    server.accept_confirm(addr(4000), client.confirm())?;

    assert!(server.ready().is_some());

    assert!(matches!(
        server.into_established(),
        Err(PacketProtectionError::ReadySubmissionRequired)
    ));

    Ok(())
}

#[test]
fn v1_session_cannot_send_ack() -> TestResult {
    let (mut client, _) = established_pair(WireProfile::V1)?;

    let mut output = [0xAA_u8; ACK_PACKET_LEN];

    assert!(matches!(
        client.send_ack(&ack_frame(), &mut output,),
        Err(PacketProtectionError::UnexpectedPacket)
    ));

    assert_eq!(output, [0xAA; ACK_PACKET_LEN]);

    // Rejected ACK must not consume a packet number.
    let len = client.send_data(b"legacy", &mut output)?;

    let packet = lestra_codec::decode_packet(&output[..len])?;

    assert_eq!(packet.header.packet_number, 1);

    Ok(())
}

#[test]
fn v2_data_and_ack_share_packet_number_space() -> TestResult {
    let (mut client, mut server) = established_pair(WireProfile::V2)?;

    let mut packet = [0_u8; MAX_DATAGRAM_LEN];
    let mut output = [0_u8; MAX_DATAGRAM_LEN];

    // Server DATA #1.
    let len = server.send_data(b"server", &mut packet)?;

    assert_eq!(
        client.receive(addr(5000), &packet[..len], &mut output,)?,
        ReceiveEvent::Data(6)
    );

    // Client DATA #1.
    let len = client.send_data(b"first", &mut packet)?;

    assert_eq!(v2::decode_packet(&packet[..len],)?.header.packet_number, 1);

    assert_eq!(
        server.receive(addr(4000), &packet[..len], &mut output,)?,
        ReceiveEvent::Data(5)
    );

    // Client ACK #2 acknowledges server DATA #1.
    let ack = ack_frame();

    let len = client.send_ack(&ack, &mut packet)?;

    assert_eq!(len, ACK_PACKET_LEN);

    let decoded = v2::decode_packet(&packet[..len])?;

    assert_eq!(decoded.header.kind, PacketType::Ack,);

    assert_eq!(decoded.header.packet_number, 2);

    assert_eq!(server.receive_ack(addr(4000), &packet[..len],)?, ack);

    // Client DATA #3.
    let len = client.send_data(b"second", &mut packet)?;

    assert_eq!(v2::decode_packet(&packet[..len],)?.header.packet_number, 3);

    assert_eq!(
        server.receive(addr(4000), &packet[..len], &mut output,)?,
        ReceiveEvent::Data(6)
    );

    Ok(())
}

#[test]
fn duplicated_ack_is_rejected() -> TestResult {
    let (mut client, mut server) = established_pair(WireProfile::V2)?;

    let ack = ack_frame();

    let mut packet = [0_u8; ACK_PACKET_LEN];

    client.send_ack(&ack, &mut packet)?;

    assert_eq!(server.receive_ack(addr(4000), &packet,)?, ack);

    assert!(matches!(
        server.receive_ack(addr(4000), &packet,),
        Err(PacketProtectionError::ReplayRejected)
    ));

    Ok(())
}

#[test]
fn forged_ack_does_not_consume_receive_packet_number() -> TestResult {
    let (mut client, mut server) = established_pair(WireProfile::V2)?;

    let ack = ack_frame();

    let mut packet = [0_u8; ACK_PACKET_LEN];

    client.send_ack(&ack, &mut packet)?;

    let mut forged = packet;

    forged[ACK_PACKET_LEN - 1] ^= 1;

    assert!(matches!(
        server.receive_ack(addr(4000), &forged,),
        Err(PacketProtectionError::Noise(_))
    ));

    assert!(!server.is_closed());

    assert_eq!(server.receive_ack(addr(4000), &packet,)?, ack);

    Ok(())
}

#[test]
fn ack_from_another_endpoint_is_rejected() -> TestResult {
    let (mut client, mut server) = established_pair(WireProfile::V2)?;

    let ack = ack_frame();

    let mut packet = [0_u8; ACK_PACKET_LEN];

    client.send_ack(&ack, &mut packet)?;

    assert!(matches!(
        server.receive_ack(addr(4001), &packet,),
        Err(PacketProtectionError::UnexpectedPeer)
    ));

    assert_eq!(server.receive_ack(addr(4000), &packet,)?, ack);

    Ok(())
}

#[test]
fn ack_output_rejection_preserves_packet_number() -> TestResult {
    let (mut client, _) = established_pair(WireProfile::V2)?;

    let ack = ack_frame();

    let mut small = [0xAA_u8; ACK_PACKET_LEN - 1];

    assert!(matches!(
        client.send_ack(&ack, &mut small),
        Err(PacketProtectionError::Codec(
            CodecError::OutputTooSmall { .. }
        ))
    ));

    assert_eq!(small, [0xAA; ACK_PACKET_LEN - 1]);

    let mut packet = [0_u8; ACK_PACKET_LEN];

    client.send_ack(&ack, &mut packet)?;

    assert_eq!(v2::decode_packet(&packet,)?.header.packet_number, 1);

    Ok(())
}

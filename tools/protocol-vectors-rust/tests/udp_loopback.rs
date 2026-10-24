//! Real 127.0.0.1 UDP socket tests of the *candidate* LEStra wire profile.
//! These TEST-ONLY identities and the "risky-raw-split" API MUST NEVER be
//! used in a deployed client/server. No VPN, TUN, or production session engine.
//! The 1024-bit replay algorithm is separately tested in replay.rs.

use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde_json::Value;
use snow::{Builder, params::NoiseParams};

const FIXTURE: &str = include_str!("../../../spec/v1/vectors/native_udp_ik.json");
const HEADER: usize = 26;
const LIMIT: usize = 1200;
const MAX_PN: u64 = 1_u64 << 32;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Packet<'a> {
    kind: u8,
    number: u64,
    dcid: [u8; 8],
    header: &'a [u8],
    body: &'a [u8],
}

fn parse_packet(bytes: &[u8]) -> Option<Packet<'_>> {
    if !(HEADER..=LIMIT).contains(&bytes.len())
        || bytes.get(..4)? != b"LSTR"
        || bytes[4] != 1
        || !(1..=6).contains(&bytes[5])
        || bytes[6..8] != [0, 0]
    {
        return None;
    }
    let body_len = usize::from(u16::from_be_bytes(bytes[24..26].try_into().ok()?));
    if body_len != bytes.len() - HEADER {
        return None;
    }
    let number = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    if bytes[5] <= 2 {
        if number != 0
            || (bytes[5] == 1 && body_len != 130)
            || (bytes[5] == 2 && body_len != 82)
        {
            return None;
        }
    } else if body_len < 16 || number >= MAX_PN {
        return None;
    }
    Some(Packet {
        kind: bytes[5],
        number,
        dcid: bytes[8..16].try_into().ok()?,
        header: &bytes[..HEADER],
        body: &bytes[HEADER..],
    })
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("committed vector JSON")
}

fn hx(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("test fixture field")).expect("hex")
}

fn socket() -> Result<UdpSocket> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(sock)
}

fn receive(sock: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
    // Allocate enough bytes to observe oversized datagrams rather than
    // truncate them silently into a seemingly valid packet.
    let mut buffer = [0_u8; 2048];
    let (size, source) = sock.recv_from(&mut buffer)?;
    Ok((buffer[..size].to_vec(), source))
}

fn send(sock: &UdpSocket, peer: &UdpSocket, bytes: &[u8]) -> Result<()> {
    assert_eq!(sock.send_to(bytes, peer.local_addr()?)?, bytes.len());
    Ok(())
}

fn aead_receive(
    bytes: &[u8],
    source: SocketAddr,
    expected_source: SocketAddr,
    kind: u8,
    expected_dcid: &[u8; 8],
    key: &[u8; 32],
    seen: &mut HashSet<u64>,
) -> Option<Vec<u8>> {
    if source != expected_source {
        return None;
    }
    let packet = parse_packet(bytes)?;
    if packet.kind != kind || &packet.dcid != expected_dcid || seen.contains(&packet.number) {
        return None;
    }
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&packet.number.to_le_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let plaintext = cipher.decrypt(
        Nonce::from_slice(&nonce),
        Payload { msg: packet.body, aad: packet.header },
    ).ok()?;
    // Commit ONLY after a successful tag; this test deliberately uses a
    // HashSet, not the production-required bounded 1024-packet replay window.
    seen.insert(packet.number);
    Some(plaintext)
}

fn key32(bytes: Vec<u8>) -> [u8; 32] {
    bytes.try_into().expect("32-byte vector key")
}

#[test]
fn real_udp_noise_ik_confirm_ready_and_bidirectional_data() -> Result<()> {
    let v = fixture();
    let hs = &v["handshake"];
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse()?;
    let prologue = hx(&v, "prologue_hex");
    let client_static = hx(&v["static_test_keys"], "client_private_hex");
    let client_public = hx(&v["static_test_keys"], "client_public_hex");
    let server_static = hx(&v["static_test_keys"], "server_private_hex");
    let server_public = hx(&v["static_test_keys"], "server_public_hex");
    let client_eph = hx(&v["ephemeral_test_keys"], "client_private_hex");
    let server_eph = hx(&v["ephemeral_test_keys"], "server_private_hex");
    let client_cid: [u8; 8] = hx(&v["cids"], "client_hex").try_into().unwrap();
    let server_cid: [u8; 8] = hx(&v["cids"], "server_hex").try_into().unwrap();

    let mut client_noise = Builder::new(params.clone())
        .local_private_key(&client_static)?
        .remote_public_key(&server_public)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&client_eph)
        .build_initiator()?;
    let mut server_noise = Builder::new(params)
        .local_private_key(&server_static)?
        .prologue(&prologue)?
        .fixed_ephemeral_key_for_testing_only(&server_eph)
        .build_responder()?;

    let client = socket()?;
    let server = socket()?;
    let mut out = [0_u8; 256];
    let mut plaintext = [0_u8; 128];

    // Flight 1: Noise IK from the client across an actual UDP socket.
    let first_header = hx(&hs["initial"], "header_hex");
    let mut first_payload = first_header.clone();
    first_payload.extend_from_slice(&client_cid);
    let first_len = client_noise.write_message(&first_payload, &mut out)?;
    let first = [&first_header[..], &out[..first_len]].concat();
    assert_eq!(first, hx(&hs["initial"], "packet_hex"));
    send(&client, &server, &first)?;
    let (incoming, source) = receive(&server)?;
    assert_eq!(source, client.local_addr()?);
    let packet = parse_packet(&incoming).expect("well-formed INITIAL");
    assert_eq!(packet.kind, 1);
    assert_eq!(packet.dcid, [0; 8]);
    let n = server_noise.read_message(packet.body, &mut plaintext)?;
    assert_eq!(&plaintext[..n], [&incoming[..HEADER], &client_cid[..]].concat());
    assert_eq!(server_noise.get_remote_static(), Some(client_public.as_slice()));

    // Flight 2: authenticated Noise response back to client.
    let response_header = hx(&hs["response"], "header_hex");
    let mut response_payload = response_header.clone();
    response_payload.extend_from_slice(&server_cid);
    let response_len = server_noise.write_message(&response_payload, &mut out)?;
    let response = [&response_header[..], &out[..response_len]].concat();
    assert_eq!(response, hx(&hs["response"], "packet_hex"));
    send(&server, &client, &response)?;
    let (incoming, source) = receive(&client)?;
    assert_eq!(source, server.local_addr()?);
    let packet = parse_packet(&incoming).expect("well-formed HANDSHAKE");
    assert_eq!(packet.kind, 2);
    assert_eq!(packet.dcid, client_cid);
    let n = client_noise.read_message(packet.body, &mut plaintext)?;
    assert_eq!(&plaintext[..n], [&incoming[..HEADER], &server_cid[..]].concat());

    assert!(client_noise.is_handshake_finished());
    assert!(server_noise.is_handshake_finished());
    let (c2s, s2c) = client_noise.dangerously_get_raw_split();
    let (server_c2s, server_s2c) = server_noise.dangerously_get_raw_split();
    assert_eq!((c2s, s2c), (server_c2s, server_s2c));

    let frames = &v["protected_packets"];
    let mut server_seen = HashSet::new();
    let mut client_seen = HashSet::new();

    // Flight 3: authenticated CONFIRM.
    let confirm = hx(&frames[0], "packet_hex");
    send(&client, &server, &confirm)?;
    let (received, source) = receive(&server)?;
    assert_eq!(aead_receive(&received, source, client.local_addr()?,
        3, &server_cid, &c2s, &mut server_seen), Some(Vec::new()));

    // Flight 4: authenticated READY.
    let ready = hx(&frames[1], "packet_hex");
    send(&server, &client, &ready)?;
    let (received, source) = receive(&client)?;
    assert_eq!(aead_receive(&received, source, server.local_addr()?,
        6, &client_cid, &s2c, &mut client_seen), Some(Vec::new()));

    // Both application directions, encrypted with distinct traffic keys.
    let data = hx(&frames[2], "packet_hex");
    send(&client, &server, &data)?;
    let (received, source) = receive(&server)?;
    assert_eq!(aead_receive(&received, source, client.local_addr()?,
        4, &server_cid, &c2s, &mut server_seen),
        Some(hx(&frames[2], "plaintext_hex")));

    let reply = hx(&frames[3], "packet_hex");
    send(&server, &client, &reply)?;
    let (received, source) = receive(&client)?;
    assert_eq!(aead_receive(&received, source, server.local_addr()?,
        4, &client_cid, &s2c, &mut client_seen),
        Some(hx(&frames[3], "plaintext_hex")));

    // Replay of the previously delivered DATA is never delivered twice.
    send(&client, &server, &data)?;
    let (received, source) = receive(&server)?;
    assert!(aead_receive(&received, source, client.local_addr()?,
        4, &server_cid, &c2s, &mut server_seen).is_none());
    Ok(())
}

#[test]
fn real_udp_rejects_bad_framing_source_and_aead_without_consuming_number() -> Result<()> {
    let v = fixture();
    let client = socket()?;
    let server = socket()?;
    let rogue = socket()?;
    let client_addr = client.local_addr()?;
    let cid: [u8; 8] = hx(&v["cids"], "server_hex").try_into().unwrap();
    let key = key32(hx(&v["handshake"], "client_to_server_key_hex"));
    let valid = hx(&v["protected_packets"][0], "packet_hex");
    let mut seen = HashSet::new();

    let mut bad_frames = vec![
        valid[..25].to_vec(),               // header truncated
        valid[..valid.len() - 1].to_vec(),  // declared body length mismatch
        { let mut b = valid.clone(); b[0] ^= 1; b }, // magic
        { let mut b = valid.clone(); b[4] = 2; b },  // major version
        { let mut b = valid.clone(); b[5] = 0xff; b }, // packet type
        { let mut b = valid.clone(); b[6] = 1; b },  // reserved flags
        { let mut b = valid.clone(); b[25] ^= 1; b }, // length
    ];
    bad_frames.push(vec![0_u8; LIMIT + 1]); // do not silently truncate oversized UDP

    for frame in &bad_frames {
        send(&client, &server, frame)?;
        let (received, source) = receive(&server)?;
        assert_eq!(source, client_addr);
        assert!(parse_packet(&received).is_none());
        assert!(aead_receive(&received, source, client_addr,
            3, &cid, &key, &mut seen).is_none());
        assert!(seen.is_empty());
    }

    // A syntactically valid packet with a mutated authenticated header fails.
    let mut altered = valid.clone();
    altered[8] ^= 1; // recipient CID, authenticated by AEAD and checked separately
    send(&client, &server, &altered)?;
    let (received, source) = receive(&server)?;
    assert!(parse_packet(&received).is_some());
    assert!(aead_receive(&received, source, client_addr,
        3, &cid, &key, &mut seen).is_none());

    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 1; // AEAD tag
    send(&client, &server, &tampered)?;
    let (received, source) = receive(&server)?;
    assert!(aead_receive(&received, source, client_addr,
        3, &cid, &key, &mut seen).is_none());
    assert!(seen.is_empty());

    // Even valid ciphertext must not migrate to another UDP source implicitly.
    send(&rogue, &server, &valid)?;
    let (received, source) = receive(&server)?;
    assert_eq!(source, rogue.local_addr()?);
    assert!(aead_receive(&received, source, client_addr,
        3, &cid, &key, &mut seen).is_none());

    // A genuine packet from the expected socket still authenticates and
    // consumes its number exactly once after all the rejected candidates.
    send(&client, &server, &valid)?;
    let (received, source) = receive(&server)?;
    assert_eq!(aead_receive(&received, source, client_addr,
        3, &cid, &key, &mut seen), Some(Vec::new()));
    assert!(seen.contains(&0));
    Ok(())
}

#[test]
fn socket_read_deadline_does_not_create_a_session() -> Result<()> {
    let sock = socket()?;
    sock.set_read_timeout(Some(Duration::from_millis(35)))?;
    let mut buffer = [0_u8; 2048];
    let err = sock.recv_from(&mut buffer).expect_err("no datagram was sent");
    assert!(matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut));
    Ok(())
}

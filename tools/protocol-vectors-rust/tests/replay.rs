//! Reference-only replay and send-counter tests for LEStra native UDP v1.
//! Not production code and not a security audit. The application state machine
//! must additionally gate packet types and session establishment.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde_json::Value;

const WINDOW_BITS: u64 = 1024;
const PACKET_LIMIT: u64 = 1_u64 << 32;
const FIXTURE: &str = include_str!("../../../spec/v1/vectors/native_udp_ik.json");

#[derive(Debug, Default, Clone)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; 16],
}

impl ReplayWindow {
    // Pure precheck: MUST NOT change state, even for an extremely large PN.
    fn candidate(&self, number: u64) -> bool {
        if number >= PACKET_LIMIT {
            return false;
        }
        let Some(highest) = self.highest else {
            return true;
        };
        if number > highest {
            return true;
        }
        let delta = highest - number;
        if delta >= WINDOW_BITS {
            return false;
        }
        let index = (delta / 64) as usize;
        let mask = 1_u64 << (delta % 64);
        self.bits[index] & mask == 0
    }

    // Must be called ONLY after successful authentication and type/CID checks.
    fn record_authenticated(&mut self, number: u64) {
        assert!(self.candidate(number), "not a fresh authenticated packet");
        match self.highest {
            None => {
                self.highest = Some(number);
                self.bits[0] = 1;
            }
            Some(previous) if number > previous => {
                let delta = number - previous;
                if delta >= WINDOW_BITS {
                    self.bits = [0; 16];
                } else {
                    let word_shift = (delta / 64) as usize;
                    let bit_shift = (delta % 64) as usize;
                    let old = self.bits;
                    let mut shifted = [0_u64; 16];
                    for i in word_shift..16 {
                        shifted[i] = old[i - word_shift] << bit_shift;
                        if bit_shift != 0 && i > word_shift {
                            shifted[i] |= old[i - word_shift - 1] >> (64 - bit_shift);
                        }
                    }
                    self.bits = shifted;
                }
                self.highest = Some(number);
                self.bits[0] |= 1;
            }
            Some(previous) => {
                let delta = previous - number;
                let index = (delta / 64) as usize;
                self.bits[index] |= 1_u64 << (delta % 64);
            }
        }
    }
}

#[derive(Debug)]
struct SendCounter {
    next: u64,
}

impl SendCounter {
    fn next_new_packet(&mut self) -> Option<u64> {
        if self.next >= PACKET_LIMIT {
            return None;
        }
        let value = self.next;
        self.next += 1;
        Some(value)
    }
}

// Explicit AEAD verification precedes all replay state updates.
// Handshake retransmissions instead reuse cached, byte-identical packets.
fn authenticate_packet(
    replay: &mut ReplayWindow,
    key: &[u8; 32],
    header: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if header.len() != 26 || header.get(0..4)? != b"LSTR" || header[4] != 1 {
        return None;
    }
    let number = u64::from_be_bytes(header.get(16..24)?.try_into().ok()?);
    if !replay.candidate(number) {
        return None;
    }
    let declared = u16::from_be_bytes(header.get(24..26)?.try_into().ok()?);
    if usize::from(declared) != ciphertext.len() {
        return None;
    }
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&number.to_le_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad: header },
        )
        .ok()?;
    replay.record_authenticated(number);
    Some(plaintext)
}

fn hex_field(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().expect("fixture field must exist")).expect("valid fixture hex")
}

fn reference_data() -> (Value, [u8; 32]) {
    let v: Value = serde_json::from_str(FIXTURE).expect("committed fixture JSON");
    let key_bytes = hex_field(&v["handshake"], "client_to_server_key_hex");
    let key: [u8; 32] = key_bytes.try_into().expect("32-byte traffic key");
    (v, key)
}

#[test]
fn ordered_reordered_and_duplicates() {
    let mut replay = ReplayWindow::default();
    for number in [0, 2, 1, 3] {
        assert!(replay.candidate(number));
        replay.record_authenticated(number);
        assert!(!replay.candidate(number));
    }
    assert_eq!(replay.highest, Some(3));
    assert!(replay.candidate(4));
}

#[test]
fn oldest_in_window_is_accepted_once() {
    let mut replay = ReplayWindow::default();
    replay.record_authenticated(0);
    replay.record_authenticated(1023);
    assert!(replay.candidate(1));
    replay.record_authenticated(1024);
    assert!(!replay.candidate(0)); // 1024 behind high watermark
    assert!(replay.candidate(1)); // 1023 behind high watermark
    replay.record_authenticated(1);
    assert!(!replay.candidate(1));
}

#[test]
fn huge_shift_expires_old_bitmap_without_allocation() {
    let mut replay = ReplayWindow::default();
    replay.record_authenticated(7);
    replay.record_authenticated(2000);
    assert_eq!(replay.highest, Some(2000));
    assert!(!replay.candidate(7));
    assert!(replay.candidate(1999));
    replay.record_authenticated(1999);
    assert!(!replay.candidate(1999));
}

#[test]
fn limit_and_nonce_exhaustion_fail_closed() {
    let mut send = SendCounter { next: PACKET_LIMIT - 2 };
    assert_eq!(send.next_new_packet(), Some(PACKET_LIMIT - 2));
    assert_eq!(send.next_new_packet(), Some(PACKET_LIMIT - 1));
    assert_eq!(send.next_new_packet(), None);
    assert_eq!(send.next_new_packet(), None);

    let mut replay = ReplayWindow::default();
    assert!(!replay.candidate(PACKET_LIMIT));
    assert!(!replay.candidate(u64::MAX));
    assert!(replay.candidate(PACKET_LIMIT - 1));
    replay.record_authenticated(PACKET_LIMIT - 1);
    assert!(!replay.candidate(PACKET_LIMIT - 1));
}

#[test]
fn tampered_high_packet_number_does_not_advance_window() {
    let (v, key) = reference_data();
    let protected = v["protected_packets"].as_array().expect("array");
    let confirm = &protected[0]; // client -> server, packet number zero
    let data = &protected[2]; // client -> server, packet number one
    let h0 = hex_field(confirm, "header_hex");
    let c0 = hex_field(confirm, "ciphertext_hex");
    let h1 = hex_field(data, "header_hex");
    let c1 = hex_field(data, "ciphertext_hex");
    let mut replay = ReplayWindow::default();

    assert_eq!(authenticate_packet(&mut replay, &key, &h0, &c0), Some(Vec::new()));
    assert_eq!(replay.highest, Some(0));
    let mut forged_header = h1.clone();
    forged_header[16..24].copy_from_slice(&500_000_u64.to_be_bytes());
    assert!(replay.candidate(500_000));
    assert!(authenticate_packet(&mut replay, &key, &forged_header, &c1).is_none());
    assert_eq!(replay.highest, Some(0));
    assert_eq!(authenticate_packet(&mut replay, &key, &h1, &c1),
        Some(b"LEStra vector test payload".to_vec()));
    assert_eq!(replay.highest, Some(1));
    assert!(authenticate_packet(&mut replay, &key, &h1, &c1).is_none());
}

#[test]
fn corrupt_tag_does_not_consume_packet_number() {
    let (v, key) = reference_data();
    let packet = &v["protected_packets"][0];
    let header = hex_field(packet, "header_hex");
    let mut ciphertext = hex_field(packet, "ciphertext_hex");
    let mut replay = ReplayWindow::default();
    ciphertext[0] ^= 1;
    assert!(authenticate_packet(&mut replay, &key, &header, &ciphertext).is_none());
    assert_eq!(replay.highest, None);
    ciphertext[0] ^= 1;
    assert_eq!(authenticate_packet(&mut replay, &key, &header, &ciphertext), Some(Vec::new()));
}

#[test]
fn receive_windows_are_per_direction_and_per_session() {
    let mut incoming = ReplayWindow::default();
    let mut outgoing = ReplayWindow::default();
    incoming.record_authenticated(0);
    assert!(outgoing.candidate(0));
    outgoing.record_authenticated(0);
    assert!(!incoming.candidate(0));
    assert!(!outgoing.candidate(0));
    // A fresh Noise session gets a fresh window and keys, not a restored nonce.
    assert!(ReplayWindow::default().candidate(0));
}

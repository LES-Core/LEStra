use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use lestra_codec::{HEADER_LEN, PacketHeader, PacketType, encode_packet_into};

use lestra_crypto::INITIAL_SIZE;

use lestra_transport_udp::{AdmissionGate, AdmissionLimits};

fn addr(host: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, host], port))
}

/// Syntactically valid INITIAL without real Noise ciphertext.
fn initial() -> [u8; INITIAL_SIZE] {
    let header = PacketHeader {
        kind: PacketType::Initial,
        destination_connection_id: [0; 8],
        packet_number: 0,
    };

    let body = [0_u8; INITIAL_SIZE - HEADER_LEN];

    let mut packet = [0_u8; INITIAL_SIZE];

    encode_packet_into(header, &body, &mut packet).unwrap();

    packet
}

#[test]
fn rejects_malformed_initial_without_allocating_state() {
    let now = Instant::now();

    let mut gate = AdmissionGate::new(AdmissionLimits::default(), now);

    assert!(!gate.allow_initial(now, addr(1, 4000), b"invalid",));

    let mut malformed = initial();
    malformed[0] ^= 1;

    assert!(!gate.allow_initial(now, addr(1, 4000), &malformed,));

    assert_eq!(gate.tracked_ips(), 0);
}

#[test]
fn per_ip_limit_cannot_be_bypassed_by_changing_ports() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        per_ip_burst: 2,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);
    let packet = initial();

    assert!(gate.allow_initial(now, addr(1, 4000), &packet,));

    assert!(gate.allow_initial(now, addr(1, 4001), &packet,));

    assert!(!gate.allow_initial(now, addr(1, 4002), &packet,));

    assert!(gate.allow_initial(now, addr(2, 4000), &packet,));
}

#[test]
fn global_limit_applies_across_independent_ips() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        global_burst: 2,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);
    let packet = initial();

    assert!(gate.allow_initial(now, addr(1, 4000), &packet,));

    assert!(gate.allow_initial(now, addr(2, 4000), &packet,));

    assert!(!gate.allow_initial(now, addr(3, 4000), &packet,));

    assert_eq!(gate.tracked_ips(), 2);
}

#[test]
fn tokens_refill_with_fractional_time() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        per_ip_burst: 1,
        per_ip_rate: 4,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);

    let source = addr(1, 4000);
    let packet = initial();

    assert!(gate.allow_initial(now, source, &packet));

    assert!(!gate.allow_initial(now + Duration::from_millis(100), source, &packet,));

    assert!(!gate.allow_initial(now + Duration::from_millis(249), source, &packet,));

    assert!(gate.allow_initial(now + Duration::from_millis(250), source, &packet,));
}

#[test]
fn source_table_has_bounded_capacity() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        max_tracked_ips: 2,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);
    let packet = initial();

    assert!(gate.allow_initial(now, addr(1, 4000), &packet,));

    assert!(gate.allow_initial(now, addr(2, 4000), &packet,));

    assert!(!gate.allow_initial(now, addr(3, 4000), &packet,));

    assert_eq!(gate.tracked_ips(), 2);

    // Existing sources remain usable.
    assert!(gate.allow_initial(now, addr(1, 4000), &packet,));
}

#[test]
fn pruning_does_not_reset_active_limits() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        per_ip_burst: 1,
        per_ip_rate: 1,
        max_tracked_ips: 1,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);
    let packet = initial();

    assert!(gate.allow_initial(now, addr(1, 4000), &packet,));

    let halfway = now + Duration::from_millis(500);

    assert_eq!(gate.prune(halfway), 0);

    assert!(!gate.allow_initial(halfway, addr(1, 4000), &packet,));

    assert!(!gate.allow_initial(halfway, addr(2, 4000), &packet,));

    let later = now + Duration::from_secs(1);

    assert_eq!(gate.prune(later), 1);
    assert_eq!(gate.tracked_ips(), 0);

    assert!(gate.allow_initial(later, addr(2, 4000), &packet,));
}

#[test]
fn ipv4_mapped_ipv6_shares_rate_limit() {
    let now = Instant::now();

    let limits = AdmissionLimits {
        per_ip_burst: 1,
        ..AdmissionLimits::default()
    };

    let mut gate = AdmissionGate::new(limits, now);
    let packet = initial();

    let ipv4 = addr(1, 4000);

    let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse().unwrap();

    assert!(gate.allow_initial(now, ipv4, &packet));

    assert!(!gate.allow_initial(now, mapped, &packet));

    assert_eq!(gate.tracked_ips(), 1);
}

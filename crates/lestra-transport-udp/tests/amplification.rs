use std::net::SocketAddr;

use lestra_crypto::{INITIAL_SIZE, RESPONSE_SIZE};
use lestra_transport_udp::AmplificationBudget;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn new_budget_has_no_credit() {
    let source = addr(4000);

    let mut budget = AmplificationBudget::new(source);

    assert_eq!(budget.remaining(), 0);

    assert!(!budget.try_reserve_send(source, RESPONSE_SIZE,));
}

#[test]
fn enforces_three_to_one_amplification_limit() {
    let source = addr(4000);

    let mut budget = AmplificationBudget::new(source);

    assert!(budget.record_received(source, INITIAL_SIZE,));

    assert_eq!(budget.remaining(), 468);

    for _ in 0..4 {
        assert!(budget.try_reserve_send(source, RESPONSE_SIZE,));
    }

    assert_eq!(budget.reserved_bytes(), 432);
    assert_eq!(budget.remaining(), 36);

    assert!(!budget.try_reserve_send(source, RESPONSE_SIZE,));

    assert_eq!(budget.reserved_bytes(), 432);
}

#[test]
fn additional_received_bytes_grant_credit() {
    let source = addr(4000);

    let mut budget = AmplificationBudget::new(source);

    assert!(budget.record_received(source, INITIAL_SIZE,));

    assert!(budget.try_reserve_send(source, 468));
    assert_eq!(budget.remaining(), 0);

    assert!(budget.record_received(source, INITIAL_SIZE,));

    assert_eq!(budget.received_bytes(), 312);
    assert_eq!(budget.remaining(), 468);
}

#[test]
fn budget_is_bound_to_original_endpoint() {
    let source = addr(4000);
    let other = addr(4001);

    let mut budget = AmplificationBudget::new(source);

    assert!(!budget.record_received(other, INITIAL_SIZE,));

    assert_eq!(budget.remaining(), 0);

    assert!(budget.record_received(source, INITIAL_SIZE,));

    assert!(!budget.try_reserve_send(other, RESPONSE_SIZE,));

    assert_eq!(budget.remaining(), 468);

    assert!(budget.try_reserve_send(source, RESPONSE_SIZE,));
}

#[test]
fn amplification_accounting_cannot_overflow() {
    let source = addr(4000);

    let mut budget = AmplificationBudget::new(source);

    assert!(budget.record_received(source, usize::MAX));
    assert!(budget.record_received(source, usize::MAX));

    assert_eq!(budget.received_bytes(), usize::MAX);
    assert_eq!(budget.remaining(), usize::MAX);

    assert!(budget.try_reserve_send(source, usize::MAX));

    assert_eq!(budget.remaining(), 0);
    assert!(!budget.try_reserve_send(source, 1));
}

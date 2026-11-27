use std::{collections::HashMap, net::SocketAddr, time::Instant};

use lestra_codec::HEADER_LEN;
use lestra_crypto::{INITIAL_SIZE, RESPONSE_SIZE};

use crate::{AmplificationBudget, ConnectionId, timer::HANDSHAKE_TIMEOUT};

const MAX_TRANSMISSIONS: u8 = 6;

pub(crate) type InitialKey = [u8; 32];

pub(crate) fn initial_key(bytes: &[u8; INITIAL_SIZE]) -> InitialKey {
    let mut key = [0_u8; 32];

    key.copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + 32]);

    key
}

pub(crate) struct InitialRecord {
    pub(crate) cid: ConnectionId,
    pub(crate) source: SocketAddr,
    pub(crate) deadline: Instant,

    initial: [u8; INITIAL_SIZE],
    response: [u8; RESPONSE_SIZE],

    budget: AmplificationBudget,
    transmissions: u8,
}

impl InitialRecord {
    pub(crate) fn new(
        cid: ConnectionId,
        source: SocketAddr,
        now: Instant,
        initial: [u8; INITIAL_SIZE],
        response: [u8; RESPONSE_SIZE],
    ) -> Self {
        let mut budget = AmplificationBudget::new(source);

        budget.record_received(source, INITIAL_SIZE);

        Self {
            cid,
            source,
            deadline: now + HANDSHAKE_TIMEOUT,
            initial,
            response,
            budget,
            transmissions: 0,
        }
    }

    /// Reserve the original HANDSHAKE transmission.
    pub(crate) fn reserve_response(&mut self) -> Option<[u8; RESPONSE_SIZE]> {
        if self.transmissions >= MAX_TRANSMISSIONS {
            return None;
        }

        if !self.budget.try_reserve_send(self.source, RESPONSE_SIZE) {
            return None;
        }

        self.transmissions += 1;

        Some(self.response)
    }

    /// Accept an exact duplicate INITIAL from
    /// the original source tuple.
    pub(crate) fn retry(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8; INITIAL_SIZE],
    ) -> Option<[u8; RESPONSE_SIZE]> {
        if now >= self.deadline || source != self.source || bytes != &self.initial {
            return None;
        }

        self.budget.record_received(source, bytes.len());

        self.reserve_response()
    }
}

pub(crate) struct InitialCache {
    entries: HashMap<InitialKey, InitialRecord>,
    capacity: usize,
}

impl InitialCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.entries.len() < self.capacity
    }

    pub(crate) fn get_mut(&mut self, key: &InitialKey) -> Option<&mut InitialRecord> {
        self.entries.get_mut(key)
    }

    pub(crate) fn contains_cid(&self, cid: ConnectionId) -> bool {
        self.entries.values().any(|entry| entry.cid == cid)
    }

    pub(crate) fn insert(&mut self, key: InitialKey, record: InitialRecord) -> bool {
        if !self.has_capacity() || self.entries.contains_key(&key) {
            return false;
        }

        self.entries.insert(key, record);

        true
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now < entry.deadline);
    }
}

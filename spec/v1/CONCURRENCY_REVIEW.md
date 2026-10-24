# LEStra v1 — concurrency and overload review

**Status: M0.3 review draft; not implemented in the production SDK.** The accompanying tests exercise reference models, not the real UDP dataplane.

## Race-sensitive security invariants

1. Every session has independent directional traffic keys and sending counters. Reservation of the next **new** packet number is serialized (single-owner session task or atomic counter) **before** encryption. A packet MUST NOT be encrypted with a previously used (key, nonce) pair. Retransmissions use cached immutable bytes; no second encryption.
2. Receive replay checks MUST NOT mutate a window until AEAD succeeds. Two workers can simultaneously verify the same ciphertext. After AEAD, a **synchronized second replay check and commit** MUST allow at most one to deliver the packet. The reference Rust concurrency test demonstrates mutex protection; it is not a prescribed production locking implementation.
3. Maintain one replay bitmap per session and direction; never reuse a bitmap across Noise handshakes, CIDs or peer identity changes. Session rekey for v1 is a fresh Noise handshake, not in-place key epochs.
4. Before expensive processing of INITIAL, enforce global and per-source rate/CPU budgets and parser length limits. After authentication, admission of a pending entry, source quotas, CID uniqueness, memory accounting and timeout deadlines must be **one atomic decision**. Independent check-then-insert operations under concurrent load are unsafe.
5. The three-to-one anti-amplification debit MUST be reserved atomically **before** sending UDP bytes, including retransmissions. A simultaneous timer and received duplicate MUST NOT independently spend the same credit.
6. Expiration, eviction, retransmission and confirmation can race. Removed pending entries MUST NOT be revived by a late packet, even when the packet was previously valid. Retiring a session invalidates CID routing, cached ciphertext and queued outbound sends. Explicit secure key disposal requirements are subject to a later implementation review.
7. Only a byte-identical, previously authenticated CONFIRM with matching CID/source and a live bounded handshake cache may resend cached READY. It does not bypass replay filtering for DATA and does not refresh a session's lifetime without limit.

## Tests and their limitations

- `tools/protocol-vectors-rust/tests/replay.rs` checks 1024-bit window behavior, a deterministic 30,000-step set-oracle model, and 16 concurrent authentic copies of one encrypted packet admitted under a lock only once.
- `tools/test_handshake_state.py` checks bounded pending entries, cached-response behavior and simultaneous admission/amplification claims using explicitly synchronized Python reference models.
- Python thread tests use explicit locks; they do not prove Rust production concurrency safety. No real UDP sockets, packet scheduling, or adversarial resource benchmarking are exercised.
- `cargo test --manifest-path tools/protocol-vectors-rust/Cargo.toml` and `python tools/test_handshake_state.py -v` must remain green.

## Review and implementation gates

A production dataplane must be separately tested with OS UDP sockets, concurrent session workers, packet loss/reordering, CID collisions, high-load handshake floods, malformed packet fuzzing, crash/reconnect, and packet-counter boundaries. Profile before choosing the final memory and rate limits.

The native v1 design is still visible as `LSTR`, has no migration or address-validation token, and is **not** claimed to evade DPI or resist all denial-of-service attacks. See [REPLAY_AND_LIMITS.md](REPLAY_AND_LIMITS.md), [STATE_MACHINE.md](STATE_MACHINE.md), and [HANDSHAKE.md](HANDSHAKE.md).

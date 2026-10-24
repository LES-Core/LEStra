# LEStra native UDP v1 — replay windows, counters and resource ceilings

> **M0.3 REVIEW DRAFT.** Reference policy for native UDP only. This is not a production implementation or an audited security claim. See [README.md](README.md) and [STATE_MACHINE.md](STATE_MACHINE.md).

## 1. Authenticated packet numbers

All protected packets (CONFIRM, READY, DATA, CLOSE) consume one monotonically increasing **64-bit wire packet number per sending direction and Noise session**. The v1 sending policy imposes a stricter ceiling: packet numbers `0 .. 2^32 - 1` are allowed, and an attempt to send packet number `2^32` MUST fail closed and reconnect using a **fresh handshake**.

The client transmits CONFIRM as C→S packet #0. The server transmits READY as S→C packet #0. Subsequent new protected packets in either direction start at #1. A retransmission is a byte-identical cached packet and **does not reserve a new number**. When the sender is uncertain whether a counter or ciphertext has been used (including process crash), it MUST abandon the session: no counter rollback, no nonce reuse, no resume using only an old CID.

Each direction uses a different Noise Split traffic key and a different counter. A second session starts its own independent counters **only with fresh Noise ephemeral keys and new session keys**.

## 2. Bounded receive replay bitmap

Maintain one receive window per direction **and authenticated session**: exactly 1024 bits of packet-seen state plus a 64-bit high watermark. Bit 0 records the highest authenticated packet number seen; bit `d` represents `highest - d`.

For received protected packet number `n`:

1. Perform bounded framing, expected source tuple, session CID/type checks and public packet-number ceiling checks before expensive authentication. Reject `n >= 2^32`.
2. Check a **pure** replay candidate predicate, without mutating the bitmap: if unseen and within the 1024-number window, or above its high watermark, it may be authenticated. Otherwise discard.
3. Verify the **whole 26-byte header** as ChaCha20-Poly1305 Additional Authenticated Data using the correct direction's key and the nonce derived from `n`.
4. On AEAD **failure**, leave the watermark and bitmap unchanged (even when the received `n` is extremely large).
5. On AEAD **success**, atomically commit the high-watermark/bitmap update and deliver the plaintext **at most once** if the state machine permits that packet type.

The first valid packet initializes the watermark. When `n > highest`, left-shift the bitmap by `n - highest`, or clear it entirely if the shift is ≥1024, set `highest=n`, and set bit 0. When `n <= highest`, require `highest-n < 1024` and an unset bit; then set that bit. The oldest allowed number is `highest-1023`. Bit shifts MUST be bounded; do not allocate proportional to an attacker-supplied packet number.

**Concurrency rule:** replay precheck and post-AEAD commit cannot be two independent unsynchronized operations. For concurrent processing, serialize commits or perform an atomic recheck when committing; exactly one packet may deliver a given authenticated packet number. The reference test models a single worker and does **not** prove thread safety.

A valid authenticated packet with a very high number can move the window and cause old delayed packets to be dropped. That is consistent with unreliable UDP delivery. Pacing and controlled send order remain important.

## 3. CONFIRM/READY exception and session state

The only allowed exception to duplicate suppression is handshake recovery: an **exact byte-for-byte duplicate of the already authenticated CONFIRM** from the original source tuple, for the same session CID, may trigger a resend of the **cached READY**, subject to a bounded retransmission budget. This exception MUST NOT re-run AEAD as a new application message, advance the replay bitmap, refresh session lifetime without limit, or deliver data.

DATA, CLOSE and READY duplicates cannot bypass the generic replay window. Data must not be exposed before the local handshake state machine permits application traffic. A client awaiting READY must not treat an early DATA packet as a substitute for READY.

## 4. Resource limits and anti-amplification

A 3:1 pre-validation UDP byte budget is **necessary but insufficient**. Source-address spoofing, CPU-intensive X25519 operations and state allocation must also be bounded.

Before processing Noise INITIAL, enforce exact canonical packet size (156 bytes in the proposed profile), type, zero flags/counters, fixed UDP payload ceiling, and cheap global/per-source rate limits. Only after these checks may the responder perform expensive cryptography. Unauthorized keys must not result in an application session.

Pending handshakes, CID reservations and cached handshake ciphertext must each have finite per-source and global bounds. All reservations require expiry and safe eviction that cannot free live authenticated sessions. Use monotonic deadlines and avoid using unauthenticated network timestamps for lifetime extension.

**Candidate deployment defaults for testing only (not normative security thresholds):**

| Configuration | Proposed initial value | Caveat |
|---|---:|---|
| Global half-open sessions | 4,096 | Must be measured against memory and CPU |
| Concurrent half-open sessions per source IP | 16 | Shared-NAT users may require higher limits |
| Global pending cache budget | 8 MiB | Account for all heap allocations, not just ciphertext |
| Handshake absolute deadline | 15 seconds | Test across mobile/high-latency links |
| Max retries per handshake flight | 5 | Retransmits do not create amplification credit |
| Max UDP payload | 1,200 bytes | Actual PMTU can be smaller |

At a minimum, track `received_bytes` and `sent_bytes` for each **unvalidated address**. Every send, including cached retransmissions, is counted; never exceed `sent_bytes <= 3 * received_bytes` until receipt of authenticated CONFIRM from that original tuple. Duplicate INITIALs from the original address may add credit if genuinely received, but rate and memory budgets still apply.

It is incorrect to count an authenticated client key or possession of a CID as proof that the source address has been validated. A verified client identity does not stop source spoofing.

## 5. Verification

The isolated Rust reference suite at `tools/protocol-vectors-rust/tests/replay.rs` tests window boundaries, reordering, duplicate rejection, large jumps, per-session independence, invalid AEAD tags and counter exhaustion. It verifies a candidate algorithm only, not the production session implementation.

```sh
cargo test --manifest-path tools/protocol-vectors-rust/Cargo.toml
python tools/test_handshake_state.py -v
```

This is automatically covered by the `Protocol vectors` CI path filter for `tools/protocol-vectors-rust/**` and `spec/v1/**`.

**Outstanding review:** realistic concurrent packet processing, source-spoofed handshake load tests, safe cleanup/eviction under memory pressure, CID collisions, minimum secure pacing and congestion behavior, crash/reconnect, independent cryptographic review and key provisioning/revocation. Wire v1 is not frozen.

References: RFC 8439, RFC 8085, Noise Protocol Framework and the LEStra v1 candidate handshake.

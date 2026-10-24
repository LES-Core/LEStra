# LEStra native UDP v1 — Handshake state machine and DoS limits

**Status: M0.3 REVIEW DRAFT.** This is a proposed behavioral contract, not a production security claim. It complements [HANDSHAKE.md](HANDSHAKE.md) and [TEST_PLAN.md](TEST_PLAN.md). No application 0-RTT.

## Security boundaries

- A handshake attempt binds the pinned server identity, original source IP/port, canonical INITIAL bytes, ephemeral key, and both receive CIDs.
- CID is an opaque routing identifier, never identity proof.
- A client is authorized only after its Noise static key is authenticated and the server ACL permits it.
- Source-address reachability is confirmed only by an authenticated CONFIRM from the original source tuple.
- Retransmit only cached, **byte-identical** encrypted messages; never re-encrypt a different message under a reused key/nonce.
- No NAT rebinding or session migration in v1: reconnect with new ephemeral keys and receive CIDs.
- DATA packets use the session's AEAD replay window; a duplicate CONFIRM is handled only by a bounded, idempotent handshake-confirmation cache.

## Client state machine

| State | Event | Required behavior | Next state |
|---|---|---|---|
| IDLE | Connect with verified server pin | Generate fresh ephemeral key and CID; send and cache INITIAL | INITIAL_SENT |
| INITIAL_SENT | Retry timeout, within limit | Retransmit unchanged INITIAL; bounded backoff/jitter | INITIAL_SENT |
| INITIAL_SENT | Authenticated HANDSHAKE with valid echo, CID and identity | Derive directional keys; send and cache AEAD CONFIRM | CONFIRM_SENT |
| INITIAL_SENT | Invalid/unsolicited HANDSHAKE | Drop; no state advance | INITIAL_SENT |
| CONFIRM_SENT | Retry timeout, within limit | Retransmit cached, identical CONFIRM | CONFIRM_SENT |
| CONFIRM_SENT | Valid READY from expected endpoint/CID | Allow application DATAGRAMs | ESTABLISHED |
| CONFIRM_SENT | Identical authenticated HANDSHAKE | May retransmit cached CONFIRM | CONFIRM_SENT |
| ESTABLISHED | Fresh authenticated DATA | Deliver once; commit replay bitmap after authentication | ESTABLISHED |
| Any live | Expiry/fatal error/counter exhaustion | Destroy session; next attempt uses new keys | CLOSED |

The client MUST NOT report established or send/deliver application DATA before authenticated READY. Premature DATA is discarded, not proof of READY.

## Server state machine

| State | Event | Required behavior | Next state |
|---|---|---|---|
| LISTENING | Bounded valid INITIAL, Noise authentication and authorized client | Allocate bounded pending entry and send cached HANDSHAKE within byte budget | HANDSHAKE_SENT |
| LISTENING | Malformed, unauthorized or over-quota INITIAL | Drop without leaking enrollment status | LISTENING |
| HANDSHAKE_SENT | Identical INITIAL from same original tuple | May resend cached HANDSHAKE if byte budget permits | HANDSHAKE_SENT |
| HANDSHAKE_SENT | Different-source replay or modified INITIAL | Reject; never reflect response to new tuple | HANDSHAKE_SENT |
| HANDSHAKE_SENT | Valid first CONFIRM from original tuple/server CID | Mark source validated; cache and send READY | ESTABLISHED |
| HANDSHAKE_SENT | Invalid CONFIRM | Drop without replay-window update | HANDSHAKE_SENT |
| ESTABLISHED | Exact duplicate of accepted CONFIRM from original tuple | May resend cached READY, but never redeliver app data | ESTABLISHED |
| ESTABLISHED | Fresh authenticated DATA from original tuple | Deliver once | ESTABLISHED |
| Any pending | Deadline/quota eviction | Erase pending keys, CIDs and cached ciphertext | CLOSED |

Server ESTABLISHED is local: it does not prove that the client has received READY. Server data may be dropped until the client establishes; reliable delivery is out of scope.

## Retransmission and replay invariants

1. Timeouts do not grant amplification credit. Every retransmission consumes existing byte credit.
2. Repeat cached ciphertext **exactly**. Do not rerun the Noise state machine on a duplicate INITIAL.
3. Fingerprint each admitted INITIAL, bind it to the original tuple, and bound the cache globally and per source.
4. Duplicate CONFIRM may only trigger a cached READY when a previously authenticated session record matches its bytes, tuple and CID. It never triggers application delivery.
5. All counters, replay windows, CID reservations, pending entries, caches and retry queues expire within finite configured budgets.
6. On process crash or counter uncertainty, create a new Noise session; never guess or restore the previous sending nonce.
7. Apply per-source and global rate limits even to retransmissions that fit the byte budget.

## Anti-amplification and resource budgets

For every unvalidated original source tuple, track actual received UDP payload bytes (rx) and sent UDP payload bytes (tx). Every initial response and retransmission counts against tx. Invariant **tx <= 3 * rx** until a valid authenticated CONFIRM.

An INITIAL is 156 bytes and a HANDSHAKE response is 108 bytes in this candidate protocol. One received INITIAL permits up to 468 bytes of cumulative responses, **not** unlimited timer-driven retransmissions. Further received duplicates may add credit only when they truly arrive from the original tuple; they remain subject to independent resource quotas.

The 3:1 rule is not sufficient against DoS. Enforce packet length limits before expensive cryptography; capped global and per-source pending sessions, bounded cache bytes, token buckets, CPU budgets, expiry, safe eviction and telemetry without leaking secrets. Stateless RETRY is not part of native v1, leaving unavoidable DH work for an admitted INITIAL.

## Verification scope and blockers

Run the accompanying dependency-free reference model with:

    python tools/test_handshake_state.py -v

This uses mock authentication flags, not actual Noise/AEAD. Packet-number replay behavior and counter exhaustion are further detailed in [REPLAY_AND_LIMITS.md](REPLAY_AND_LIMITS.md). Tests cannot establish encryption correctness, nonce safety, concurrency safety or distributed DoS resistance.

Before approving v1, verify independent Rust Noise vectors, packet AAD and nonce mapping; concurrency-safe CID/replay-cache behavior; loss/reordering/network stress; and key enrollment/revocation policy.

References: Noise Protocol Framework (https://noiseprotocol.org/noise.html), RFC 8085 (https://www.rfc-editor.org/rfc/rfc8085), RFC 9000 §8 (comparison only; LEStra is not QUIC).

# LEStra v1 — Handshake packet-loss and overload review (M0.3)

**Status: deterministic model-only tests, not real UDP integration or a security audit.** Complements [HANDSHAKE.md](HANDSHAKE.md), [STATE_MACHINE.md](STATE_MACHINE.md) and [REPLAY_AND_LIMITS.md](REPLAY_AND_LIMITS.md).

## Flight recovery contract

The native UDP handshake consists of INITIAL → HANDSHAKE → CONFIRM → READY. Its server and client cache precisely the same serialized/encrypted packet for a retransmission; a retransmission cannot allocate a new nonce. If any flight is lost, the sender's bounded retry or a duplicate of the previous flight may cause a cached packet to be resent. A timer **does not** increase server amplification credit.

The client MUST NOT send or expose application DATA until it authenticates READY. The responder may locally establish after CONFIRM; losing READY can leave responder established and client failed, so server state must expire safely. DATA remains unreliable and application retransmissions are outside native v1.

Every handshake flight has a finite retransmission count and the overall client attempt has an absolute monotonic deadline. Exponential backoff MUST be capped and SHOULD include random jitter to prevent synchronized bursts. Delayed packets arriving after terminal failure cannot resurrect the old client session.

Server HANDSHAKE and READY retransmissions also require finite per-flight budgets **even after** source-address validation. Repeated authenticated CONFIRM is not a command to send infinitely many READY packets. Production implementations additionally require rate limits per identity/source and bounded cache lifetime.

## Reference test model

The deterministic virtual-time event scheduler in [../../tools/test_handshake_network.py](../../tools/test_handshake_network.py) exercises:

- Baseline handshake and the loss of each of INITIAL, HANDSHAKE, CONFIRM and READY independently.
- A mixed-loss scenario, duplicated/reordered flights and delayed READY.
- Infinite network loss versus bounded retry counts/deadline (fail closed).
- Duplicate INITIAL/CONFIRM response limits independent of the 3:1 amplification limit.
- Source-address spoofing and a burst of 2,000 attempted half-open admissions with finite state/cache budgets and expiry.

Its flights use symbolic fixed-size byte arrays and mock successful validation from [../../tools/test_handshake_state.py](../../tools/test_handshake_state.py). It does **not** parse the 26-byte actual wire header, perform Noise/X25519 or decrypt tags, open UDP sockets or drive a real congestion controller. Runtime defaults (100 ms initial RTO, 800 ms maximum RTO, 2.2-second deadline, five transmissions per flight) are **model fixtures only**, not recommended deployment settings.

Run with:

    python tools/test_handshake_network.py -v

The CI workflow runs this test when its own file, the state model, or the protocol specification changes.

## Production design review still required

1. Real client/server integration over loopback and externally constrained networks; socket send queue and kernel UDP buffer behavior.
2. Authenticated session expiration and late-packet tombstones, concurrent timers versus eviction, and CID reuse after crashes.
3. Performance of X25519 under unauthorized-client floods, source spoofing and shared-NAT effects; empirical resource quotas.
4. Actual pacing and congestion response before high-throughput traffic, following RFC 8085. Handshake retry backoff is **not** data-plane congestion control.
5. Small path MTU, packet truncation, reordering and malformed input fuzzing, including reject-before-allocation.
6. Formal review of loss recovery and the Noise transcript/AAD/counter contracts by someone independent of the implementation.

This draft does **not** approve the v1 wire format for release.

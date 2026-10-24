# LEStra v1 — M0.3 verification plan (revision 3)

**Status:** Candidate deterministic reference vectors, standalone Rust/Noise verifier, and replay/handshake reference models are present. Successful automated checks are not an independent security audit; concurrent/network stress testing and security review remain open.

## Local generator and smoke tests

Install a separate Python environment and use the version pinned in `tools/requirements-vectors.txt`:

```bash
python -m pip install -r tools/requirements-vectors.txt
python tools/generate_vectors.py --check
python tools/test_vectors.py -v
```

To regenerate and review fixture differences:

```bash
python tools/generate_vectors.py
```

This Python reference is deliberately written for determinism and fixture generation only. It uses the `cryptography` library for X25519 and ChaCha20-Poly1305, but it manually orchestrates Noise state and HKDF. **Do not ship it as a security implementation** or regard successful self-checks as independent cross-implementation agreement. Fixture contains exposed **TEST-ONLY** secret keys.

## Expected canonical facts

- INITIAL: 26-byte header + 130-byte Noise message = 156-byte UDP payload.
- HANDSHAKE: 26-byte header + 82-byte Noise message = 108-byte UDP payload.
- CONFIRM/READY: 26-byte header + 16-byte tag = 42-byte UDP payload each.
- Protected data uses 26-byte header as ChaCha20-Poly1305 AAD, per-direction Noise `Split()` key, packet-number-derived nonce.
- `DATA` payload capacity at 1200-byte outer UDP payload cap: 1158 bytes.

## Negative cases required before freeze

1. Unsupported magic/version/type, nonzero flags, lengths, truncated or trailing bytes; no panic/large allocation.
2. Mismatched pinned server static public key, unauthorized client key, wrong Noise payload header echo, swapped client/server CIDs.
3. Mutated AEAD header or ciphertext/tag, wrong key direction, invalid nonce, reused packet number.
4. Replayed protected packet; reordered unseen packet within 1024-packet window; invalid high packet number does not move window.
5. Duplicate INITIAL from a new source; floods under source-spoofing; amplification never exceeds 3:1 prior to confirmation.
6. Lost INITIAL, HANDSHAKE, CONFIRM and READY; cached byte-identical retransmission; READY retry on a duplicate CONFIRM; no duplicate application delivery.
7. Crash/restart, session expiry and 2^32 counter limit: fresh session and new ephemeral key mandatory.
8. Shrinking MTU, congestion/loss and large number of untrusted half-open sessions.
9. Independent Rust & non-Rust fixture verification with fixed ephemeral keys and full Noise transcript byte match.

## Merge/implementation gate

- Documentation and fixture generation can be reviewed as **M0.3 draft**.
- **Do not approve the wire format for stable v1 or merge a crypto implementation** until an independent verifier reproduces the reference results and a reviewer signs off nonce/AAD, replay logic and handshake state machine.
- Rust constant `PROTOCOL_MAJOR_VERSION` remains `0` until wire freeze.

## Independent verification implementation

- [`RUST_VERIFICATION.md`](RUST_VERIFICATION.md) documents the isolated `snow`/RustCrypto verifier at `tools/protocol-vectors-rust`. Each revision must pass its GitHub CI tests; tests do not constitute an independent security assessment.
- [`STATE_MACHINE.md`](STATE_MACHINE.md) describes explicit client/server transitions and byte-budget invariants.
- [`REPLAY_AND_LIMITS.md`](REPLAY_AND_LIMITS.md) specifies packet-number acceptance, non-mutating replay prechecks, after-AEAD commits, and candidate resource bounds. Rust reference cases live in `tools/protocol-vectors-rust/tests/replay.rs`.
- [`CONCURRENCY_REVIEW.md`](CONCURRENCY_REVIEW.md) records race-sensitive invariants and remaining real-network review gates. Deterministic reference tests include a set-oracle sequence and concurrent duplicate/admission cases; these are not production tests.
- `tools/test_handshake_state.py` provides **model-only** tests (mock authentication, not Noise) for retransmission, replay/ACL gates, amplification and half-open session/cache quotas; run with `python tools/test_handshake_state.py -v`.
- [`.github/workflows/protocol-vectors.yml`](../../.github/workflows/protocol-vectors.yml) executes Python fixtures/model tests and Rust validation for relevant changes, including the M0.3 documentation branch.

Do not mark M0.3 wire freeze complete until Rust vector jobs pass and remaining security review gates are formally closed.

## Virtual-time loss and overload simulations

- [NETWORK_FAULTS.md](NETWORK_FAULTS.md) documents deterministic packet-loss, timeout, duplicate, delayed READY and admission-burst model tests.
- Run `python tools/test_handshake_network.py -v` in CI alongside the existing Python and Rust fixture verifiers.
- Simulation does not replace real UDP socket tests or satisfy the independent security-review gate.

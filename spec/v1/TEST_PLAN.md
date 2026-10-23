# LEStra v1 Test Plan — revision 2

**Status:** Planned tests, not generated/executed vectors. A successful parser test is not a cryptographic security review.

## Wire codec

- Verify exact 26-byte header offsets, `LSTR` magic, big-endian fields and all proposed type values.
- Validate size boundaries: 0, 25, 26, 27, 1199, 1200, 1201 bytes.
- Reject unknown major/type, nonzero flags, trailing body bytes, mismatched declared length, invalid handshake counters and oversized datagrams.
- Round-trip known fixed fixture bytes, independently from Rust.

## Handshake

- Fixed test-only initiator/responder static and ephemeral keys.
- Exact Noise IK byte sequence and transcript hash, encrypted handshake payload, responder identity binding, client ACL and server CID binding.
- Verify wrong server pin, unauthorized client, transcript tampering, replayed INITIAL and altered HANDSHAKE reject.
- Verify byte-identical handshake retransmission and that no server application payload is emitted before CONFIRM.
- Stress simultaneous half-open handshakes and forged source addresses; enforce resource and amplification budgets.

## Data, AEAD and replay

- Record fixed session-direction keys, header bytes, packet number, nonce, plaintext, ciphertext/tag (only in test vectors).
- Test pkt#0, pkt#1, window boundaries, reordered valid packets, duplicates, tag/header modification.
- Assert bitmap changes only after valid AEAD; invalid large-counter packets do not advance the replay window.
- Check direction key separation, counter limit, restart causing new Noise handshake and session key.
- Confirm CONFIRM, DATA and CLOSE share directional packet-number space.

## Network / integration

- UDP packet loss, jitter, duplication, reordering, truncation, NAT rebinding and MTU shrink.
- Payload > negotiated limit errors without fragmentation.
- Fairness and pacing under a saturated link; measure throughput, latency and CPU.
- Build a second non-Rust codec consumer for independent interoperability.

## Required artifacts before approval

`spec/v1/vectors/*.json` with exact verified binary fixtures (hex), a generator with pinned dependency versions, and an independent verifier. No fixture content should be guessed or written by hand.

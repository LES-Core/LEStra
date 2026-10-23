# LEStra v1 - interoperability and negative test plan (M0.3)

Status: design draft. Actual vectors are not generated.

## Canonical positive vectors (required prior to implementation)

- Publicly reproducible, fixed X25519 identity/ephemeral key materials **for tests only** and expected Noise IK handshake bytes/transcript hashes.
- Known plaintext, associated-data/header bytes, expected AEAD ciphertext/tag, and exact nonce value for first and boundary packets.
- Both initiator-to-responder and responder-to-initiator outputs, epoch transitions and key separation.
- Parser endianness, exact byte lengths and maximum packet size.
- Independent Rust and non-Rust decoding equivalence.

## Mandatory negative tests

| Case | Expected result |
|---|---|
| Unknown pinned server static key | Handshake rejection |
| Authenticated but unauthorized client key | No session/application access |
| Bit flip in signed/AEAD-associated header | Authentication failure |
| Duplicate protected packet | Drop; no delivery twice |
| Out-of-window replay | Drop |
| Reordered in-window valid packet | Deliver at most once |
| Invalid, unknown or critical version/flags | Reject |
| Oversized/truncated handshake or data packet | Reject without panic/unbounded allocation |
| Forged RETRY token | Reject |
| Nonce/counter near exhaustion | Rekey or fail closed; never wrap |
| Rekey with old epoch packet | Apply explicitly specified overlap policy |
| Address spoofing during migration | No uncontrolled amplification |
| Unknown crypto suite/fallback request | No downgrade |
| Fuzzed arbitrary packet bytes | No panic, OOM or secret disclosure |

## Measurement

Run latency, loss, jitter and throughput tests across constrained MTU, packet loss, reorder, NAT rebinding and saturated uplinks. Establish a bounded-rate sending policy; benchmark overhead without claiming security from speed results.

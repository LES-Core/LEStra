# LEStra v1 — M0.3 consistency and security-review findings

**Status: review draft; not an independent security assessment.**
Date: 2026-10-24. Scope: the native UDP v1 candidate, test-only Rust/Python reference harnesses and SDK separation. Keep the production workspace's `PROTOCOL_MAJOR_VERSION = 0`; these findings do not constitute wire freeze.

## Executive disposition

**Documentation/test PR: REVIEWABLE, once all CI checks are green.**
**Wire-format freeze or production-secure VPN release: NOT APPROVED.**

The Noise IK and ChaCha20-Poly1305 deterministic fixtures have been reproduced by a separate Rust implementation, and real loopback sockets, replay models, negative parser fixtures, property tests, and fault simulations are present. These are useful conformance evidence; they are *not* an external audit, formal proof, congestion-controlled dataplane, or production implementation.

## Fixed/tested consistency findings

| ID | Finding | Resolution in M0.3 branch |
|---|---|---|
| WIRE-01 | Test-only parser accepted CONFIRM/READY with nonzero packet numbers and DATA/CLOSE at packet #0, while the draft requires specific counter ranges. | Parser now structurally rejects those cases and includes four negative byte-vector tests. |
| WIRE-02 | Loopback tests had a second, less strict framing parser that could drift from the tested reference parser. | Loopback harness calls the shared test-only `decode_envelope` function. |
| WIRE-03 | Documentation incorrectly still called the independent Rust/Noise fixture verification pending after CI success. | Updated the status, while retaining the security-review blocker. |
| WIRE-04 | It was unclear where application versus VPN payload semantics are selected. | Resolved contract below: the data payload is **opaque bytes**, with mode interpretation outside the native wire profile. |

## Responsibility boundaries (normative candidate)

| Layer | Responsibilities | Must not do |
|---|---|---|
| Framing codec | Length, magic, version, flags, message type, public CID/counter and body-shape constraints, bounded borrowed slices. | Authenticate a peer, infer a trust decision from a CID, decrypt or deliver data. |
| Noise handshake | Authenticate server pinned static key, verify client static key, bind header echo, CIDs and prologue to transcript. | Treat source address or authorization as cryptographically implied by the handshake. |
| Session AEAD | Authenticate complete 26-byte header as AAD and ciphertext using the correct directional Noise Split key and unique nonce. | Omit AAD because a convenience library only accepts empty AAD. |
| Session state | Enforce role, expected endpoint, CID mapping, handshake transition, bounded replay commit, lifetime and retransmission cache. | Deliver application DATA before confirmation or make ciphertext retransmission with a reused nonce. |
| Server authorization | Apply ACL, revocation and resource policy to authenticated client keys. | Assume authentication automatically confers routing rights or address validation. |
| Application / VPN adapter | Interpret authenticated DATA bytes, e.g. application's messages or IP packets, as configured out of band. | Require TUN, GUI, proprietary accounts or a platform route in the core SDK. |

**No implicit payload mode:** Native v1 DATA carries opaque bytes. Both peers MUST agree out of band whether those bytes represent an application datagram or a VPN/IP packet. Core LEStra has no default IP forwarding, DNS behavior, packet compression, routing rules or implicit protocol sniffing. If future versions add in-band multiplexing, payload content types or negotiation, this needs an explicitly versioned and transcript-authenticated extension. That future feature is **not** present in the v1 header, so the current fixtures remain unchanged.

## Remaining blocking decisions and risks

1. **Cryptographic security review:** A qualified reviewer needs to examine Noise IK identity binding, handshake retransmission under replay, session key exposure/zeroization, exact ChaCha20-Poly1305 nonce lifecycle, AAD, concurrent counters and process-crash semantics. Fixed test vectors do not establish these broader properties.
2. **CID lifecycle:** Document collision handling across half-open and active sessions, cleanup order, tombstones, CID reuse and load under source-spoofed INITIAL; implement and stress-test in production.
3. **Resource/DoS resilience:** Pending handshake ceilings, amplification reservations, authenticated READY retransmit limits, per-source token buckets and CPU budgets have only been model-tested. Validate concurrency and memory under real server load; the proposed numeric budgets are *test candidates*, not safe global defaults.
4. **Congestion control and PMTU:** Native UDP must pace and react to sustained loss, not merely send packets at line rate. Require concrete dataplane policy and tests before production traffic. 1200-byte cap is a draft baseline and must be adapted to deployment path constraints.
5. **Provisioning and revocation:** The server/client static-key enrollment, pinned-server-key rotation, key revocation, ACL refresh, compromised-key handling and failure responses need operational policy and integration tests.
6. **Unknown version / unknown capability:** Native v1 does not negotiate cipher suites or versions; reject unsupported versions and do not auto-downgrade to a less secure profile. A QUIC/TLS fallback is a separate authenticated transport design and not interchangeable with Noise by accident.
7. **Operational interoperability:** Real production client and server, malformed-packet fuzzing, independent implementation interoperability and platform socket/backpressure tests remain to be built. The current reference oracle is deliberately not `lestra-codec`.

## Acceptance gates

A **documentation PR** can merge after code review and green relevant CI if every changed spec document keeps its *review draft* status and no production constants are incremented. In contrast, **stable wire v1** requires explicit protocol/security review and interoperability tests; **production-ready VPN** additionally requires network congestion/PMTU/routing/DNS testing and deployment hardening. These three milestones must not be conflated.

Recommended next engineering task: develop M0.4 `lestra-codec` in its own branch, using the reviewed *candidate* framing and tests with a clear unstable API. Do not publish a stable protocol version or secure-transport claim merely because the parser is complete.

References: [Noise Protocol Framework rev.34](https://noiseprotocol.org/noise.html), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085), [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899).

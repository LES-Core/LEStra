# LEStra Native UDP Wire Protocol v1 - design draft

Status: **DRAFT / NON-IMPLEMENTABLE until review gates close**. Document revision: M0.3-draft-1.

This document defines an intended interoperable, transport-independent encrypted datagram session over native UDP. It does **not** define QUIC, HTTP/3 or TCP/TLS profiles. It is not evidence of cryptographic security, a stable wire format, or a production implementation.

Normative terms (MUST, SHOULD, MAY) use RFC 2119 and RFC 8174 meanings. Draft fields tagged **TBD** are not valid implementation constants and MUST NOT be shipped as an interoperable protocol without a subsequent normative revision.

## 1. Scope and trust model

- Client MUST have an authenticated, out-of-band copy of the expected server X25519 static public key (key pinning). TOFU is not the default.
- Server MUST authenticate the client's static public key and separately consult an authorization policy. Unknown keys MUST NOT get application access.
- Static identity keys MUST be distinct from ephemeral keys. Provisioning, secure storage and revocation are deployment concerns; server MUST have a revocation mechanism.
- The base protocol exposes unreliable, unordered application datagrams. VPN/IP processing lives in a separate adapter. No reliable streams, fragmentation or anonymity guarantee in v1.
- An endpoint MUST NOT treat an encrypted connection on an alternative transport as equivalent to native UDP Noise unless an explicit profile documents and authenticates the security boundary.

## 2. Cryptographic profile (proposed, review pending)

Proposed Noise name: `Noise_IK_25519_ChaChaPoly_SHA256` as defined in the Noise Protocol Framework. The client knows the responder static key in advance. The responder authenticates the initiator static key, then applies an ACL. This means the first handshake message has the identity-hiding properties (and limits) of Noise IK, **not** anonymity from the server or guaranteed metadata hiding.

- Native session key material MUST be derived using the reviewed Noise state machine and its `Split()` output, with a fixed initiator-to-responder / responder-to-initiator direction mapping.
- Public handshake labels, application prologue, capability binding and transcript encoding are **TBD**. An application MUST NOT use arbitrary unverified prologues to negotiate unsupported versions.
- Noise handshake cipher nonces and transport-data packet nonces are different state machines. Implementers MUST NOT reuse a key/nonce combination.
- Data-header authentication and additional per-epoch key derivation are described below as requirements, but exact construction is **TBD**, pending vector-backed cryptographic review.
- Initial default suite has no PQ claim. Algorithm agility is **not** a reason to offer unauthenticated downgrade.

## 3. Packet families and framing

All multibyte integers will be encoded in network byte order (big-endian). A single UDP datagram contains exactly one LEStra envelope; trailing bytes and inconsistent lengths MUST be rejected. The parser MUST perform bounded, allocation-safe validation before crypto operations.

| Family | Purpose | Authentication rule |
|---|---|---|
| `INITIAL` | Client handshake initiation | Noise IK handshake payload, additionally subject to DoS policy |
| `RETRY` | Stateless address-validation challenge, if needed | Cryptographically verifiable server token; **format TBD** |
| `HANDSHAKE` | Responder handshake output | Noise handshake authentication |
| `DATA` | Protected application datagram or authenticated control message | Per-direction session AEAD |
| `CLOSE` | Authenticated session close notification | Session AEAD only |

**Do not allocate codepoint values yet.** Proposed header elements (byte offsets and sizes TBD): protocol discriminator, wire major version, family/type, flags, destination connection identifier, packet counter/epoch where applicable, and payload length where needed. Every field affecting packet interpretation MUST be authenticated by the relevant handshake transcript, token MAC or data AEAD associated data. No unauthenticated extension may silently change security settings.

A fixed, parseable discriminator aids robust parsing but also creates a DPI fingerprint. Concealment/obfuscation belongs in an explicit separate transport profile; it MUST NOT compromise authentication. Reserved flags MUST cause rejection until extension rules are standardized.

## 4. Handshake state machine

```text
CLIENT: Idle -> InitialSent -> ServerAuthenticated -> Established
SERVER: Stateless -> (RetrySent) -> Handshaking -> Authorized -> Established
EITHER: Established -> Closing -> Closed
EITHER: Any state -> Failed (terminal)
```

1. Client loads an authenticated expected server identity, chooses a version/profile allowed by local policy and initiates a Noise IK handshake.
2. Server validates input sizes and anti-amplification limits before expensive resource allocation. Under pressure it MAY issue a stateless RETRY token; retry binding, expiry and MAC format remain TBD.
3. Noise responder handshake proves possession of the pinned responder static key. The server authenticates the initiator key and checks authorization **before delivering any application payload**.
4. Version, capability and role selection MUST be transcript-bound. Silent fallback from an authenticated to unauthenticated profile is forbidden.
5. Only after both peers complete authentication and key setup may the session enter `Established`. Application 0-RTT data is forbidden in v1.
6. Duplicate, reordered and timed-out handshake messages require bounded retransmission and state expiry. Retry behavior MUST NOT enable address-amplification loops.

**Review blocker:** Noise IK is a two-message handshake, but server assurance that the client received responder output may require an explicit first authenticated client data packet or confirmation message. v1 cannot assert symmetric session confirmation without specifying that exchange.

## 5. Protected datagrams, replay and nonce safety

- Each key direction MUST have independent monotonically increasing packet numbers. A packet number MUST never be reused with a key, including after restart.
- Data AEAD MUST authenticate the complete external security-relevant header as associated data, in addition to the encrypted payload. Concrete header encoding, nonce derivation and epoch binding are **TBD**.
- Receivers MUST reject unauthenticated packets without forwarding. Duplicate packet numbers MUST be discarded. Reordering inside a bounded receive window MAY be accepted only once. A candidate replay-window update MUST be committed **after successful AEAD verification**.
- A session MUST close or rekey before nonce exhaustion; sending MUST stop on uncertainty about persisted counters or epoch state. Rekey thresholds and mechanics are **TBD**.
- Old and new key epochs MUST use cryptographically separated keys and distinct replay windows. Concurrent epoch acceptance, maximum overlap and explicit acknowledgement are **TBD**.
- Authenticated `CLOSE` is advisory and MUST NOT be interpreted as proof of transport delivery. No unauthenticated UDP packet can terminate an established session.

## 6. Connection IDs, NAT rebinding, migration

A connection identifier is an opaque routing handle, never proof of peer identity. Accepting a valid packet from a new source address does not automatically authorize unlimited replies to that address. Address validation, response amplification limits, and migration acceptance MUST be specified and tested before enabled. v1 can initially disable migration and require reconnect on path change.

## 7. MTU, loss and congestion

- `DATAGRAM` delivery is best effort: loss, duplication or reordering may occur before crypto processing. Applications MUST NOT assume successful delivery from `send` completion.
- No application-level fragmentation in v1. The SDK exposes a negotiated maximum payload and rejects oversize messages.
- Start with a conservative configurable UDP payload limit; avoid relying on IPv4 fragmentation. The final default and discovery method are **TBD**.
- A high-speed UDP tunnel MUST define congestion and pacing behavior consistent with RFC 8085. A sender MUST NOT assume the application may transmit at unlimited rate simply because UDP has no built-in congestion control.

## 8. Versions, extensibility, downgrade

Wire major version and application/library semantic version are distinct. No v0/v1 fallback outside an explicitly configured policy. Unknown critical extensions MUST fail closed. Unknown non-critical extensions may be ignored only when length-delimited and authenticated. Version negotiation format and protected transcript encoding are **TBD**. Do not announce v1 interoperability until vectors for canonical encoding exist.

## 9. Error behavior and limits

Implementations MUST use bounded allocations and validate packet size/field ranges before dispatch. No panic on malformed packets. Unauthenticated inputs MUST NOT expose detailed cryptographic failure causes or client-enrollment status. Rate limiting is REQUIRED on unauthenticated request paths. Internal diagnostic logging MUST NOT dump secret keys or plaintext payloads.

## 10. Review gates before M0.4/M0.5

1. Fix all codepoint values, byte offsets, lengths and canonical wire encodings; reject unknown formats.
2. Fix exact Noise prologue, handshake payload content, token format and anti-amplification policy.
3. Fix session transcript/capability binding, session confirmation and role-specific key mapping.
4. Specify AEAD nonce construction, epochs, rekey and packet-number limits with reviewable security argument.
5. Produce reproducible positive/negative cryptographic test vectors from trusted implementations.
6. Specify MTU/pacing limits, parser resource ceilings, fuzz/property test matrix and cross-implementation compatibility tests.

## References

- Noise: https://noiseprotocol.org/noise.html
- RFC 8439: https://www.rfc-editor.org/rfc/rfc8439
- RFC 8085: https://www.rfc-editor.org/rfc/rfc8085
- RFC 2119: https://www.rfc-editor.org/rfc/rfc2119
- RFC 8174: https://www.rfc-editor.org/rfc/rfc8174

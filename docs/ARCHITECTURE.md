# LEStra Architecture (M0.2)

Status: **Draft — architectural baseline; not a wire specification.**

## Goals

- Provide a portable, embeddable secure session/datagram protocol independent of a VPN application.
- Make UDP the primary transport while permitting independently specified alternative secure transport profiles.
- Support IP tunneling through an external adapter; neither TUN nor routing is a prerequisite for the protocol SDK.
- Provide a Rust API first and a versioned C ABI later.
- Optimize for low latency and reasonable resistance to blocking without claiming undetectability.

## Non-goals (v1)

- Anonymous routing, censorship resistance against all adversaries, peer-to-peer mesh, multi-hop forwarding, or undetectability.
- Homemade cryptographic primitives, a full congestion-control algorithm, or a reliable stream protocol in M0.
- A proprietary dependency on LEStra GUI or on a hosted LEStra service.

## Component and dependency boundaries

| Component | Responsibility | Must not depend on |
|---|---|---|
| `lestra-core` | Versioned protocol concepts, identities and session contracts | Tokio, OS networking, GUI, TUN |
| `lestra-codec` | Parse/serialize specified wire messages with bounded inputs | Tokio, crypto key management, TUN, GUI |
| `lestra-sdk` | Public session and datagram API, configuration | Desktop application or VPN UI |
| Future `lestra-crypto` | Handshake orchestration and AEAD session state | TUN, GUI |
| Future `lestra-transport-udp` | UDP I/O and transport lifecycle | TUN, GUI |
| Future `lestra-transport-quic` | QUIC transport profile, negotiated security properties | TUN, GUI |
| Future `lestra-tunnel` | TUN/IP adapter and OS routing integration | GUI |
| Future apps | CLI, VPN client and server applications | N/A |

Core crates must remain usable without creating a network socket. Transport crates MUST expose explicit security profiles, not implicitly treat TLS and Noise as interchangeable.

## Session architecture

1. Caller supplies the expected server identity (or explicitly selects an alternative trusted verifier).
2. A transport connection is established. For native UDP, a mutually authenticated handshake establishes traffic keys.
3. Session state maintains separate transmit and receive key material, packet counters, replay windows and epochs.
4. The application transmits unreliable datagrams through the session API. A VPN adapter can send inner IP packets as datagram payloads.
5. Loss, reordering, path changes and reconnects are observable through explicitly specified APIs. Reliable streams are not a v1 requirement.

Native UDP will initially use a Noise IK-style pinned-static-key trust model as a **candidate**, to be fixed by M0.3 after test vectors and an implementation review. Detailed key schedule, associated-data layout and wire encoding remain undecided.

## Transport profiles

- **UDP-native:** own handshake, anti-replay and AEAD protection. Primary profile for M1–M3.
- **QUIC:** alternative profile with QUIC/TLS authenticated transport; do not assume the Noise-native packet and cryptographic semantics are identical. QUIC DATAGRAM is an option where supported.
- **TCP/TLS:** optional fallback, with explicit disclosure of head-of-line blocking behavior and limited scope.

Transport adaptation, padding and cover traffic MUST NOT silently downgrade authentication or confidentiality. Client fallback is policy-driven and must be auditable.

## API and embedding guarantees

- The base SDK works without elevated permissions, TUN, DNS interception or a running LEStra daemon.
- Support applications that already have an event loop; avoid forcing callers into a single global runtime.
- Expose message reliability, ordering, maximum payload and backpressure semantics explicitly.
- Use stable protocol versioning independent of Rust crate semver and C ABI versioning.
- A second implementation must be able to interoperate using public specifications and test vectors.

## Implementation stages

M0.2: threat model, trust assumptions, boundaries and decisions; M0.3: normative handshake and wire format; M0.4: codec with fuzz tests and vectors; M0.5: cryptographic sessions; M1: functional UDP transport; M2: standalone embedded SDK proof; M3: VPN adapter.

## Open questions for M0.3

- Static-key provisioning, revocation and enrollment UX.
- Exact Noise pattern, cipher/hash choices, transcript and downgrade protections.
- Stateless anti-amplification challenge and responder DoS behavior.
- Packet classification, authenticated header fields, nonce and epoch encoding.
- Key rotation, sequence exhaustion, reconnect and migration rules.
- Datagram limits, PMTU behavior and traffic shaping interfaces.

## References

- Noise Protocol Framework: https://noiseprotocol.org/noise.html
- RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
- RFC 9221 (QUIC DATAGRAM): https://www.rfc-editor.org/rfc/rfc9221
- RFC 9484 (CONNECT-IP): https://www.rfc-editor.org/rfc/rfc9484

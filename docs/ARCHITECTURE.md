# LEStra Architecture (draft)

## Goals

1. A reusable secure datagram/session protocol, independent from VPN software.
2. Native UDP first; alternate QUIC and TLS transports later.
3. Optional IP tunneling adapter (TUN) outside the protocol core.
4. Rust SDK initially; versioned C ABI as a later separate package.

## Dependency boundaries

- `lestra-core`: portable, runtime-independent shared types.
- `lestra-codec`: wire framing/codec after public specification; no Tokio, TUN or GUI.
- `lestra-sdk`: application-facing API, initially a minimal facade.
- Future transport crates depend on protocol primitives, not desktop code.
- Future VPN application depends on SDK; SDK does not depend on VPN application.

## Unresolved decisions

- Threat model and authentication / trust model.
- Wire packet format, versioning, frame boundaries, replay protection.
- Noise handshake profile and use of transport-native TLS.
- Datagram size / MTU, fragmentation and congestion policy.
- Reliable message channel semantics and interoperability test vectors.

No encryption, transport security or network forwarding is currently implemented.

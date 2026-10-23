# LEStra Protocol Specifications

The binary wire protocol is **not defined yet**. This directory holds normative, versioned specifications and interoperability vectors.

M0.2 defines security and architectural boundaries in [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) and [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md). These documents are **drafts**, not normative message formats.

The M0.3 specification must cover:

1. Protocol version, packet types, length limits, byte order and extension rules.
2. Identity provisioning, authentication and negotiated capabilities.
3. Handshake transcript, peer/key verification and DoS controls.
4. AEAD authenticated data, counters, nonces, epochs, replay acceptance and rekey.
5. Datagram delivery semantics, PMTU and error handling.
6. Interoperability vectors and adversarial negative tests.
7. Profile-specific security for native UDP, with later independent QUIC/TLS profiles.

**Normative keywords** MUST, MUST NOT, SHOULD, MAY will have RFC 2119 / RFC 8174 meaning when introduced in a versioned specification.

No encryption, secure handshake, or VPN forwarding has been implemented yet.

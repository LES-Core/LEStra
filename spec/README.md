# LEStra Protocol Specifications

Wire protocol documentation is independent from Rust crate semantic versions, the public SDK and any future C ABI.

- [`v1/README.md`](v1/README.md): **M0.3 revision 3 candidate** framing, authentication, routing, datagrams and lifecycle.
- [`v1/HANDSHAKE.md`](v1/HANDSHAKE.md): exact Noise IK message composition, client/server CIDs, CONFIRM/READY and cached retransmission policy.
- [`v1/TEST_PLAN.md`](v1/TEST_PLAN.md): fixtures, negative tests and review gates.
- [`v1/vectors/native_udp_ik.json`](v1/vectors/native_udp_ik.json): deterministic **test-only** reference fixtures with exposed private test keys (never production secrets).
- [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md): SDK and transport boundaries.
- [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md): baseline security objectives.

Tools: `tools/generate_vectors.py`, `tools/test_vectors.py`, and pinned `tools/requirements-vectors.txt`.

**This is a review draft, not an approved or independently audited protocol.** Keep `PROTOCOL_MAJOR_VERSION=0` in source until all M0.3 review gates close.

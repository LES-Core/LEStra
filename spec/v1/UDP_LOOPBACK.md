# LEStra native UDP v1 — loopback verification (M0.3)

**Status: test-only integration harness. Not the LEStra server/client or audited production cryptography.**

The Rust test module `tools/protocol-vectors-rust/tests/udp_loopback.rs` opens actual OS UDP sockets bound to `127.0.0.1:0` and verifies the proposed v1 envelope with the same deterministic fixtures as the Noise/AEAD vector tests.

## Coverage

1. Generates Noise IK INITIAL and HANDSHAKE using `snow` with intentionally public test-only static and ephemeral keys; sends the actual packet bytes through client and server UDP sockets and checks the decrypted header echo.
2. Confirms initiator identity on the responder, exact Noise handshake ciphertext agreement with checked-in reference bytes, and directional Split key agreement.
3. Sends CONFIRM and READY via real sockets; authenticates the **whole 26-byte header** as AEAD Associated Data; then delivers DATA in both directions using separate traffic keys.
4. Sends a duplicate DATA packet and verifies the test receiver delivers the packet number only once.
5. Rejects truncated, length-mismatched, unknown-version/type, reserved-flags, and oversized datagrams before accepting them.
6. Rejects a mutated AEAD tag or recipient CID without consuming the valid packet number, and rejects a correct encrypted packet arriving from another UDP source tuple.
7. Confirms that a read timeout without any incoming datagram does not establish a session.

## Isolation and limitations

The receiver in this test is a small **fixture-only** parser and a `HashSet` of accepted packet numbers. It does **not** replace the 1024-bit bounded replay window, session management, resend/pacing logic or real source-authentication policy in the production engine. The client and server use one local process and deterministic test identities; it is **not** a test of an independent deployed client/server binary, high-rate load, packet loss, NAT rebinding or PMTU discovery.

For packet loss and bounded retransmission, refer to [NETWORK_FAULTS.md](NETWORK_FAULTS.md) (virtual-time model). For bounds and replay semantics, refer to [REPLAY_AND_LIMITS.md](REPLAY_AND_LIMITS.md).

```sh
cargo test --manifest-path tools/protocol-vectors-rust/Cargo.toml --test udp_loopback
```

The existing `Protocol vectors` workflow runs this together with all other isolated Rust reference tests. M0.3 remains **REVIEW DRAFT**, and `PROTOCOL_MAJOR_VERSION` in the actual Rust workspace must remain 0 until the security review and wire freeze.

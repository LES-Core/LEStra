# LEStra native UDP v1 — negative vectors and fuzzing

**Status: M0.3 review draft. Framing-only test support, not production codec.**

`tools/protocol-vectors-rust/src/lib.rs` provides a pure, allocation-free, zero-copy reference decoder of the 26-byte header and at most 1200 bytes of UDP datagram data. It rejects invalid framing, reserved flags, unknown types/versions, inappropriate CIDs, handshake lengths, invalid counter ranges, and malformed protected-body lengths.

`spec/v1/vectors/parser_cases.json` contains full hexadecimal **positive** and **negative** byte sequences. The standalone `tests/parser.rs` asserts that negatives fail and valid packets are decoded using borrowed slices, and it runs bounded property-based `proptest` inputs in CI. A corrupted ciphertext with valid framing may still parse: **only AEAD authentication can reject it**. The test-only UDP loopback parser is separate; the production codec will be designed in M0.4.

```sh
cargo test --manifest-path tools/protocol-vectors-rust/Cargo.toml --test parser
```

An optional separate `cargo-fuzz` target exists at `tools/protocol-vectors-rust/fuzz/fuzz_targets/decode_envelope.rs`. Normal GitHub CI **does not** run unbounded fuzzing. With nightly toolchain and cargo-fuzz installed:

```sh
cd tools/protocol-vectors-rust
cargo +nightly fuzz run decode_envelope -- -max_len=4096 -max_total_time=60
```

Passing tests and fuzzing are not a proof of memory safety, DoS resistance or production cryptographic correctness. Replay, authenticated headers, allocation and congestion limits, key management and independent security review remain separate gates.

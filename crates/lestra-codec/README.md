# lestra-codec — M0.4

**Status: unstable implementation of the native UDP candidate header. Not a secure VPN or final wire protocol.**

Transport-agnostic, allocation-free Rust framing API, with borrowed packet views and
serialization into caller-provided buffers. No Tokio, TUN, sockets, OS privileges,
VPN application or cryptographic dependencies.

`decode_packet()` checks magic, draft version, type, reserved flags, lengths,
CID and packet-number structural constraints. `encode_header()` produces the
exact 26-byte header (to be authenticated as AAD); `encode_packet_into()`
writes a complete envelope only when size and shape checks succeed.

**Important:** A decoded body is *not* authenticated; it may contain attacker
supplied ciphertext. Session and crypto layers remain responsible for Noise
identity/authentication, AAD verification, anti-replay, source binding and ACL.

Tests use all 7 positive and 27 negative committed binary fixtures in
`spec/v1/vectors/parser_cases.json`, check byte-exact roundtrips and boundaries,
and run deterministic mutation checks, without new crate dependencies.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, and `cargo test --workspace --all-features`.

`lestra-core::PROTOCOL_MAJOR_VERSION` remains `0`. The codec's
`DRAFT_WIRE_MAJOR = 1` indicates candidate on-wire fixture bytes only.

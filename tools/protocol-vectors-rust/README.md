# LEStra standalone protocol vector verifier

This Cargo package is intentionally **outside the LEStra production workspace**.

Run its tests from the repository root:

```shell
cargo test --manifest-path tools/protocol-vectors-rust/Cargo.toml
```

Tests use upstream `snow 0.10.0` to reproduce Noise IK handshake bytes and RustCrypto ChaCha20-Poly1305 to reproduce authenticated data packets from `spec/v1/vectors/native_udp_ik.json`.

The `risky-raw-split` feature, public deterministic private keys, and fixed ephemeral-key injection are used **only in fixture tests**. Do not copy them into production LEStra packages.

A green test only demonstrates agreement with these specific candidate vectors and does not replace a full security review. Also run:

```shell
python tools/generate_vectors.py --check
python tools/test_vectors.py -v
python tools/test_handshake_state.py -v
```

The Python reference requires dependencies in `tools/requirements-vectors.txt`; the handshake state model uses only the Python standard library.

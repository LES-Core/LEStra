# LEStra

**LEStra** is an experimental, embeddable secure networking protocol from **LES Core**.
The project aims to support low-latency datagram transport, adaptable network transports,
and VPN tunneling as an optional application built on the protocol.

> **Status:** early development. No secure transport, VPN, or production protocol is implemented yet.
> Do not use this repository for real-world security or privacy protection.

## Design principles

- Independent protocol core and embeddable SDK; no mandatory VPN or GUI dependency.
- Transport-agnostic application API with a native UDP path as the initial target.
- Versioned public protocol specification before committing to a wire format.
- Well-reviewed cryptographic primitives; no custom cryptographic algorithms.
- Explicit interop, security, and performance tests before claiming compatibility or security.

## Workspace

| Crate | Purpose |
|---|---|
| `lestra-core` | Shared protocol primitives |
| `lestra-codec` | Packet codec (pending specification) |
| `lestra-sdk` | Public application integration API |

## Develop

Install the stable Rust toolchain using [rustup](https://rustup.rs/).

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --workspace --all-targets --all-features
```

## Documentation

See [Architecture](docs/ARCHITECTURE.md), [Specification](spec/README.md),
[Contributing](CONTRIBUTING.md), and [Security](SECURITY.md).

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT),
at your option. The `LEStra` project name and branding are not separately licensed by
these software licenses; no trademark rights are granted by this statement.

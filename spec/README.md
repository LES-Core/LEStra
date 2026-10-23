# LEStra Protocol Specifications

These documents are versioned independently of Rust crate semver and of the later C ABI.

- [`v1/README.md`](v1/README.md): **M0.3 design draft** for native UDP framing, authentication, data packet handling and security review gates.
- [`v1/TEST_PLAN.md`](v1/TEST_PLAN.md): required interoperability and adversarial tests; vectors have not yet been generated.
- [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md): component boundaries and transport independence.
- [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md): baseline attacker capabilities and security objectives.

**No stable LEStra v1 wire constants, cryptographic encoding or interoperability guarantee exist yet.** M0.4 codec work requires closing the review gates listed in the v1 draft. Keywords MUST, SHOULD, MAY use RFC 2119 and RFC 8174 meanings.

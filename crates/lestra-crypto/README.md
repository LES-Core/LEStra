# lestra-crypto — M0.5, milestone 1

**Experimental Noise IK handshake only — NOT a complete secured LEStra session.**

This crate composes `snow = 0.10.0` with `lestra-codec` to produce and
verify the native UDP v1 INITIAL (156 bytes) and HANDSHAKE (108 bytes).

Implemented:
- Pinned server X25519 static public key on the client side.
- Decrypted/Noise-authenticated client X25519 static key checked against an
  explicitly allowed key on the server, before sending a response.
- Exact 26-byte outer header echoed in the encrypted Noise payload.
- Client and server receive CIDs bound to the authenticated Noise exchange.
- Expected UDP source tuple checked for the client's response; responder
  records the initiating tuple for future CONFIRM validation.
- One-time typed handshake transitions and immutable cached INITIAL/response
  bytes, preventing accidental handshake retransmission encryption.
- No network sockets, GUI, global event loop, TUN, or VPN requirement.

**Deliberately not implemented:**
- CONFIRM, READY, DATA, CLOSE or a session-level ready/send API.
- Extracting raw Noise Split traffic keys: do **not** enable
  `snow/risky-raw-split` in the production workspace.
- Using the normal Snow transport methods as an AEAD substitute: their API
  cannot authenticate the full LEStra 26-byte header as required by the draft.
- Quota/accounting and per-source handshake CPU rate limits (belong to the
  UDP session orchestration layer; before invoking this crate).
- Retry timers, expiry, collision-safe CID allocator, secure key storage,
  rotation/revocation and replay window. They remain M0.5 blockers.

The handshake's `VerifiedNoise` type exposes only CIDs, peer address and
transcript hash; it intentionally does not expose a session send API or
transport crypto key material. Its name does *not* mean LEStra application
traffic may be sent.

Identity keys and CIDs are provisioned by the caller. In production, static
keys and ephemeral Noise keys must be generated with secure randomness, CIDs
fresh and unpredictable, peer keys provisioned/pinned out of band, and
server authorization revocable. Keys in `spec/v1/vectors/` are publicly
disclosed **test identities** and must not be used in deployment.

Testing: `cargo test -p lestra-crypto`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`.

Next milestone: review an explicit-AAD-capable Noise Split/AEAD integration,
then implement authenticated CONFIRM/READY and replay-safe DATA transitions.
The current M0.3 wire format is still a review draft.

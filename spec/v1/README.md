# LEStra Native UDP Wire Protocol v1 — M0.3 revision 3

**Status: REVIEW DRAFT, not an approved public wire standard and not audited.**

This document supersedes the M0.3 revision 2 proposal for purposes of review. It defines a *candidate* byte encoding and session contract. The Rust API, VPN adapter, TUN, Desktop UI, hosted LES Core infrastructure, and QUIC/TCP profiles remain outside the protocol. RFC 2119/8174 keywords will become normative **only after formal approval**.

## Scope and security baseline

- Client–server UDP, one LEStra packet per UDP datagram, bounded/unordered/unreliable application DATAGRAM delivery.
- Client MUST possess an authenticated, pinned server X25519 static public key. Server authenticates client X25519 static public key and applies a separate authorization policy. No default TOFU.
- Noise suite proposal: `Noise_IK_25519_ChaChaPoly_SHA256` (Noise rev. 34). Fixed prologue: exact ASCII `LEStra/native-udp/v1` (no NUL).
- No 0-RTT, reliable streams, IP fragmentation, session migration, stateless RETRY or in-place traffic key rotation for v1. A changed network path requires reconnect.
- No claim of metadata anonymity or guaranteed DPI evasion; `LSTR` visibly fingerprints the native UDP profile.

## Packet envelope

All integer fields use **big-endian** serialization (exception: the Noise ChaChaPoly nonce encoding, explained below). One UDP datagram MUST contain exactly one complete envelope. Extra or short bytes cause rejection.

| Byte offset | Size | Name | Meaning |
|---:|---:|---|---|
| 0 | 4 | magic | Bytes `4c 53 54 52` (`LSTR`) |
| 4 | 1 | major | `01` |
| 5 | 1 | type | See codepoints below |
| 6 | 2 | flags | Always `0000` in initial version |
| 8 | 8 | dcid | Destination connection ID (opaque handle) |
| 16 | 8 | packet_number | Big-endian 64-bit; zero for unprotected handshake |
| 24 | 2 | body_len | Exact body bytes following header |
| 26 | N | body | Noise handshake message or AEAD ciphertext+tag |

Header length is **26 bytes**. `body_len` and UDP datagram length MUST agree. All protection-sensitive fields must be authenticated either through an encrypted Noise handshake payload's verbatim header echo, or through transport AEAD associated data.

| Code | Name | Body | Protection |
|---|---|---|---|
| `01` | INITIAL | Noise IK message 1 | Noise-authenticated, replayable prior to response |
| `02` | HANDSHAKE | Noise IK message 2 | Noise-authenticated |
| `03` | CONFIRM | Empty plaintext, 16-byte tag | Session AEAD |
| `04` | DATA | Application bytes + 16-byte tag | Session AEAD |
| `05` | CLOSE | Empty plaintext, 16-byte tag | Session AEAD |
| `06` | READY | Empty plaintext, 16-byte tag | Session AEAD |

Unrecognized packet types, unsupported `major`, non-zero flags, bad lengths and impossible header combinations are rejected; untrusted inputs MUST NOT trigger unrestricted allocation.

## Connection identifiers and handshake

The initiator randomly generates a fresh, nonzero 64-bit **client receive CID**, and the responder randomly generates a fresh, nonzero 64-bit **server receive CID**, with collision checks among live sessions. A CID is *not* a secret or identity proof.

1. **INITIAL**: `dcid=0000000000000000`, `packet_number=0`. Its Noise payload is `verbatim 26-byte INITIAL header || client receive CID` (34 bytes). The resulting Noise IK message 1 is exactly **130 bytes**, giving **156 total UDP payload bytes**.
2. **HANDSHAKE**: `dcid=client receive CID`, `packet_number=0`. Its Noise payload is `verbatim 26-byte HANDSHAKE header || server receive CID` (34 bytes). Noise IK message 2 is **82 bytes**, giving **108 total UDP payload bytes**.
3. Both parties MUST compare the decrypted header echo byte-for-byte to the actual outer header. The client MUST ensure the response uses its chosen receive CID. Both sides verify identity/ACL and Noise transcript before accepting a new session.
4. **CONFIRM**: the client's first protected packet, `packet_number=0`, with empty plaintext and `dcid=server receive CID`. The responder MUST NOT send or deliver application data before validating CONFIRM.
5. **READY**: responder's first protected packet, `packet_number=0`, with empty plaintext and `dcid=client receive CID`. Client enters `Established` only after a valid READY (server enters it after valid CONFIRM). Application DATA starts at packet number 1 on either direction.

`CONFIRM`/`READY` provide explicit loss recovery rather than relying on application traffic to confirm a handshake. Full transcript and retransmission rules: [HANDSHAKE.md](HANDSHAKE.md).

### Session-level authenticated encryption

Noise `Split()` supplies **two different CipherState keys**, ordered **initiator→responder** and **responder→initiator**. LEStra's protected datagrams use ChaCha20-Poly1305 with these directional keys and explicit packet-number nonces, applying the *whole 26-byte header as AEAD associated data*.

- For each protected packet with wire `packet_number = n`, the ChaChaPoly nonce is `00000000 || LE64(n)` (12 bytes). The 64-bit `n` in the header remains big-endian. This matches the Noise ChaChaPoly nonce layout but MUST be validated with an independent implementation.
- Both directions have separate transmit counters and receive replay windows. `CONFIRM`, `READY`, `DATA` and `CLOSE` share **one directional counter space** (only permitted types for each role are used).
- Authenticate before delivering any message. Replay bitmap updates ONLY AFTER successful AEAD verification. An invalid packet carrying a high counter MUST NOT advance the receive window.
- Use a **1024-packet sliding window**. Receive ciphertexts out of order only if authentic and previously unseen. Reject any duplicate authenticated packet except byte-identical cached handshake retransmissions processed by the handshake retry handler.
- For v1, send **at most 2^32 protected packets per direction** (packet numbers `0...2^32-1`). Fresh handshake and new traffic keys are mandatory before exhaustion. Never restore a previously used nonce counter after restart.
- Do not add a separate ad hoc HKDF for data encryption: use the actual Noise `Split()` directional cipher states with authenticated associated data, or a reviewed compatible implementation. A library that only authenticates the empty AD string does **not** satisfy this profile.

**Implementation compatibility warning:** `snow::StatelessTransportState` supports explicit nonce numbers but its `write_message/read_message` interface does not expose AEAD associated data. LEStra must not silently omit header authentication or assume those methods implement this design. Before M0.5 choose a reviewed engine with explicit `EncryptWithAd`/`DecryptWithAd` support or specify a formally reviewed alternative.

### Transport, capacity and session behavior

- Initial UDP datagram payload cap: **1200 bytes, including 26-byte header and 16-byte AEAD tag**. Maximum application DATA is **1158 bytes**; no LEStra-level fragmentation. Reject larger application datagrams instead of relying on IP fragmentation. Deployment path-MTU requirements may reduce this cap.
- Native UDP does not provide retransmission for DATA; a successful API `send` does not imply delivery, ordering or reliability.
- Before confirmation, maintain source-address resource quotas and a response-byte amplification budget of **at most 3×** bytes received for that address; the server's 108-byte HANDSHAKE fits within the 156-byte INITIAL budget. Restrict concurrent half-open states, set expiry deadlines and rate limits.
- No stateless RETRY in v1. No implicit CID migration or NAT-rebinding acceptance; reject packets from an unexpected remote endpoint and require a new connection.
- Sending MUST implement congestion response and pacing before enabling high-throughput production traffic (RFC 8085); do not assume arbitrary line-rate UDP injection is acceptable.
- Authenticated CLOSE is advisory. Unauthenticated closure or version renegotiation is not permitted.

## Test vectors and approval gates

- [HANDSHAKE.md](HANDSHAKE.md) defines handshake and retry policy.
- [TEST_PLAN.md](TEST_PLAN.md) describes required testing and acceptance criteria.
- [STATE_MACHINE.md](STATE_MACHINE.md) defines handshake transitions, replay-cache and anti-amplification rules.
- [RUST_VERIFICATION.md](RUST_VERIFICATION.md) describes independent test-only Rust Noise/AEAD fixture checks (pending CI verification).
- [vectors/native_udp_ik.json](vectors/native_udp_ik.json) contains **test-only deterministic candidate vectors** generated from [../../tools/generate_vectors.py](../../tools/generate_vectors.py) (relative path: `tools/` at repository root). All private keys in vectors are **public test values**, NEVER production identities.

**Blocking before wire freeze / M0.4 and M0.5:** independent Rust/Noise verification of the deterministic transcript and Split keys; protocol review of CID, authenticated header and retry-state handling; reproducible positive and negative codec fixtures; DoS and congestion review. Until resolved, keep `PROTOCOL_MAJOR_VERSION=0` in Rust source, even though the draft header uses proposed `0x01`.

References: https://noiseprotocol.org/noise.html , https://www.rfc-editor.org/rfc/rfc8439 , https://www.rfc-editor.org/rfc/rfc8085 , https://www.rfc-editor.org/rfc/rfc8899

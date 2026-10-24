# LEStra Native UDP v1 — IK Handshake and Confirmation

**Status: M0.3 REVIEW DRAFT. Not a deployed or independently audited secure handshake.**

## Prerequisites

- Noise protocol: `Noise_IK_25519_ChaChaPoly_SHA256`, revision 34.
- Prologue: exact bytes of ASCII `LEStra/native-udp/v1`.
- Noise IK pre-message: responder static public key (`<- s`), already authenticated by the initiator.
- Initiator's X25519 static key must be on server ACL before application access; unknown clients fail closed.
- Fresh ephemeral X25519 secret keys from the OS CSPRNG on every new attempt. Never reuse deterministic vector keys in production.
- Suite and wire major are fixed, not negotiated during INITIAL. No unprotected downgrade or automatic trust-on-first-use.

## Exact Noise IK pattern

```text
<- s
...
-> e, es, s, ss
<- e, ee, se
```

Noise uses `EncryptAndHash` / `DecryptAndHash` to bind payload ciphertext to the handshake hash. In LEStra, handshake plaintext payloads explicitly echo the outer header, ensuring an altered routing/type/size/flags field does not silently change protocol behavior.

### Flight 1: INITIAL (initiator -> responder)

1. Initiator picks random nonzero 8-byte `client_recv_cid` and ephemeral key.
2. Serialize a 26-byte INITIAL header with `dcid=0`, `packet_number=0` and `body_len=130`.
3. Noise message 1: `e.pub[32] || EncryptAndHash(s.pub)[48] || EncryptAndHash(initial_header[26] || client_recv_cid[8])[50]` = **130 bytes**.
4. Send exactly one 156-byte UDP payload. Never attach application data.
5. Server first checks length, outer header, quotas and rate limits. Server performs the Noise read and checks `header_echo==outer_header` before trusting `client_recv_cid`.
6. Server authenticates initiator static public key against server ACL; unknown/disabled client keys cannot establish a session.

### Flight 2: HANDSHAKE (responder -> initiator)

1. Responder picks random nonzero 8-byte `server_recv_cid` and fresh ephemeral key; registers CID only if not already used by another live session.
2. Serialize HANDSHAKE header with `dcid=client_recv_cid`, `packet_number=0`, `body_len=82`.
3. Noise message 2: `e.pub[32] || EncryptAndHash(handshake_header[26] || server_recv_cid[8])[50]` = **82 bytes**.
4. Server sends a 108-byte UDP payload to the original source, respecting anti-amplification quotas.
5. Client checks that outer HANDSHAKE `dcid` equals its chosen CID; validates Noise message, compares header echo and stores `server_recv_cid`.
6. Noise IK is now complete and both peers hold directional cipher states from `Split()`; these are not yet sufficient to authorize application traffic.

### Flight 3: CONFIRM (initiator -> responder)

Send an AEAD-protected empty plaintext with header `type=03, dcid=server_recv_cid, packet_number=0, body_len=16`; full UDP payload is **42 bytes**. AEAD associated data is the entire header. Server checks tag and permitted state, then marks the connection `Established` but first sends READY.

### Flight 4: READY (responder -> initiator)

Send an AEAD-protected empty plaintext with header `type=06, dcid=client_recv_cid, packet_number=0, body_len=16`; UDP payload is **42 bytes**. Client marks the session `Established` after authentication. All DATA packets begin at `packet_number=1` per direction.

## Retransmission and idempotency policy

- UDP handshake uses stop-and-wait retransmission with bounded deadline, count and exponential backoff with jitter; exact runtime timeouts are an implementation config rather than wire bytes.
- Retransmit **exactly the cached complete INITIAL, HANDSHAKE, CONFIRM or READY packet bytes**. Do not regenerate encrypted bytes with a reused nonce.
- Responder keeps a bounded cache of handshake fingerprints plus source address, chosen CIDs, status and cached HANDSHAKE/READY ciphertext. A byte-identical duplicate INITIAL from its original source may trigger replay of cached HANDSHAKE; it MUST NOT trigger a new Noise response using reused handshake keys and new payload bytes.
- A byte-identical duplicate CONFIRM from the original source may trigger re-sending cached READY **even if the packet counter has already been accepted by replay window**. This is an idempotent handshake-specific exception, never duplicate application delivery.
- INITIAL arriving from a different address but with a previously observed fingerprint MUST be rejected, not used to reflect a response to the new address.
- Responder's total pre-confirmation outgoing bytes to an unvalidated address MUST be <=3 times bytes received at that address, including retransmissions. If the credit is insufficient, drop/delay a resend.
- Limit retransmission count and total handshake duration, bound per-source and global caches; expiry or fatal errors require a **new** handshake with fresh ephemeral secret, CIDs and traffic keys.
- Responder MUST NOT forward any application data until valid CONFIRM. Client MUST NOT expose `Established` or send application DATA until a valid READY.

## Security and integration limits

- CID routes packets but does not authenticate identities. Initial `dcid=0` is not a persistent global state handle.
- Enforce exact source socket tuple (or defined endpoint binding) until migration has its own reviewed protocol; reconnect after NAT/path change.
- Retransmitted encrypted handshake bytes do not increment new cipher nonce counters. Cached ciphertext must have bounded lifetime and must be erased with expired session state.
- Never surface detailed unauthenticated errors that reveal enrolled keys, server ACL, or internal key states.
- A compromised server/client private identity key is outside protocol confidentiality guarantees; deployment requires a documented revocation mechanism.
- `snow` can serve as an **independent handshake oracle** after integration, but its public stateless transport API currently does not supply LEStra's header AAD contract; do not silently pass empty AD.

## Open review requirements

1. Independently regenerate the IK transcript hash, ciphertexts and `Split()` traffic keys (e.g., using `snow` with fixed deterministic RNG for test mode).
2. Independently verify the transport AEAD header-associated-data construction with the exact directional Noise cipher keys.
3. Security review of INIT replay cache, source binding, collision policy, concurrent retransmission and amplification accounting.
4. Full state-machine property tests for loss, reordering, session eviction, crash and reconnect.
5. Define key enrollment/revocation operational contract in the server implementation spec.

See [README.md](README.md) for complete wire fields.

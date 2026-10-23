# LEStra Native UDP Protocol v1 — M0.3 revision 2

**Status:** REVIEW DRAFT. Not an approved interoperable wire protocol. Do not implement cryptography from this draft or claim production security.

This revision replaces open-ended concepts with concrete proposed encodings and explicit review gates. LEStra's application SDK, VPN tunnel and GUI are outside this specification. RFC 2119/8174 uppercase keywords are normative only **after** this draft is approved.

## 1. Protocol scope and profile

* Primary profile: UDP, one LEStra envelope per UDP datagram, no trailing bytes.
* Two peers: initiator (client) and responder (server). Client has an authenticated pinned X25519 responder public key; server maintains an ACL of permitted initiator static keys.
* Cryptographic handshake candidate: `Noise_IK_25519_ChaChaPoly_SHA256` (Noise rev. 34). 0-RTT application data is forbidden.
* Unreliable, unordered application datagrams only. No reliable streams, fragmentation, migration, key-epoch overlap, QUIC or TCP fallback in native v1.
* No wire format depends on LEStra Desktop, TUN, proprietary accounts, daemon, or GUI.

## 2. Canonical common header (proposal)

All integers are **unsigned big-endian** except counters interpreted as nonce inputs, which are separately defined below. All lengths count bytes.

| Offset | Size | Name | Description |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `LSTR` = `4c 53 54 52` |
| 4 | 1 | major | `0x01` |
| 5 | 1 | type | `0x01 INITIAL`, `0x02 HANDSHAKE`, `0x03 CONFIRM`, `0x04 DATA`, `0x05 CLOSE` |
| 6 | 2 | flags | Must equal zero (big-endian), otherwise reject |
| 8 | 8 | destination CID | Opaque random receiver-chosen connection ID |
| 16 | 8 | packet number | Only for protected packet types; zero for INITIAL/HANDSHAKE |
| 24 | 2 | body length | Length of bytes following this header, max configurable |
| 26 | N | body | Packet-type-dependent |

Header size is **26 bytes**, not the earlier illustrative 18 bytes. Canonical decoding rejects truncated packets, body length mismatch, unknown types, nonzero reserved flags and unsupported versions. Payload and UDP datagram size limits are separately enforced before allocation.

**Open issue — CID bootstrap:** INITIAL uses destination CID zero; HANDSHAKE provides a responder-assigned CID in its **encrypted Noise handshake payload**; CONFIRM and DATA use that CID. Client-selected CID, and how the server addresses initial handshake retransmits without storing unauthenticated state, need specification. Do not treat CID as an authentication credential.

**Open issue — fingerprinting:** `LSTR` is a deliberately recognizable native profile marker, not an obfuscated wire form. Any future obfuscated transport requires its own authenticated profile.

## 3. Handshake profile and transcript binding

Handshake flow:

```text
C                                  S
INITIAL  [Noise IK message 1] --->
              <--- HANDSHAKE [Noise IK message 2]
CONFIRM [authenticated data] ---->
DATA    [authenticated AEAD]  <--->
```

The intended Noise IK pattern is:
```text
<- s
...
-> e, es, s, ss
<- e, ee, se
```

Noise **prologue candidate**: fixed UTF-8 bytes `LEStra/native-udp/v1` (no NUL). Application-selected fields, version, transport profile and security-relevant options **must be bound to the Noise transcript** via canonical handshake payloads; do not silently negotiate cryptographic algorithms from unauthenticated header fields.

* INITIAL contains Noise message 1 and an encrypted, canonical client handshake payload.
* HANDSHAKE contains Noise message 2 and the encrypted server handshake payload. Server must authenticate client key and check ACL before making application data available.
* CONFIRM is the client's first authenticated transport packet, with no application data, confirming that it processed HANDSHAKE. Server must not deliver or originate app data for the session before accepting CONFIRM.
* Session establishment on the client occurs after authenticating HANDSHAKE; on server after authenticating CONFIRM.
* Retransmissions repeat **identical cached handshake bytes**; a retransmission must not re-run Noise or consume the same nonce for different plaintext. Sessions have bounded lifetime and retransmit count.
* Unknown client keys, incorrect pinned server keys, and mismatched transcripts fail closed.

**Review blockers:** canonical encrypted handshake payload layout, fixed lengths, ephemeral-key generation/testing, CID binding, confirmation frame syntax and Noise implementation API must be finalized before code.

## 4. Data AEAD and replay (candidate)

* Directional traffic keys come from Noise `Split()`, initiator→responder and responder→initiator respectively. They must not be interchanged or used for unrelated protocols.
* For each direction, a **new session** starts the protected packet number at zero. Increment once for every **new** protected packet; no wrap. Never resume counters after process restart: perform a fresh handshake.
* Proposed ChaCha20-Poly1305 nonce: 12 bytes = four zero bytes followed by the packet number encoded little-endian (`0x00000000 || LE64(packet_number)`). This must be checked against the selected library API, Noise's cipher-state nonce convention and independent test vectors.
* Proposed AEAD additional authenticated data is the **entire 26-byte header**. Body is ciphertext followed by the standard 16-byte authentication tag. Invalid tags never reach applications.
* Replay protection: a 1024-packet sliding bitmap for each **direction and session**, accepting authentic, unseen packets inside the window. Check candidacy before decryption, commit bitmap changes **only after successful AEAD authentication**.
* A `CONFIRM` uses the client→server protected packet-number space. `CLOSE` uses that sender's space. Control and data packets consume one shared directional counter.
* Strict limit for initial implementation: **at most 2^32 protected packets sent in a session per direction**, after which stop and establish a fresh session. Do not rotate keys in-place in v1.
* Retransmitted handshake ciphertext is a byte-for-byte repeat; post-handshake application datagrams are not retransmitted by LEStra.

**Review blockers:** validate key export/usage against Noise's transport-cipher API; prove nonce uniqueness, replay safety, correct handshake–transport domain separation and robust counter exhaustion behavior. This is a candidate construction, **not an audited cryptographic design**.

## 5. Session lifecycle and resource limits

```text
CLIENT: Idle -> InitialSent -> HandshakeVerified -> ConfirmSent -> Established -> Closed
SERVER: Listening -> (PendingHandshake) -> HandshakeSent -> ConfirmVerified -> Established -> Closed
```

* INITIAL must pass fixed-size checks, bounded rate limiting and resource-budget checks.
* For this baseline, do not offer stateless RETRY until token and address-binding rules have undergone review. Cap unvalidated-address amplification to at most three times the number of bytes received on that address; stronger restrictions may be necessary.
* Enforce bounded half-open state, deadlines, LRU eviction, per-source/account rate controls, and deterministic teardown.
* An authenticated CLOSE is advisory; unauthenticated CLOSE is invalid. Session IDs must not imply peer identity.
* Disable connection migration / NAT rebinding in native v1: an authenticated packet arriving from another remote address triggers **reconnect**, not implicit path migration.
* Reject oversized outgoing payloads. Baseline UDP payload cap recommendation: **1200 bytes including the LEStra envelope**, subject to path constraints and deployment validation; applications learn the current maximum data payload. Do not rely on IP fragmentation.
* Pacing, congestion response and fairness are necessary before throughput claims; consult RFC 8085 and RFC 8899 for UDP/PMTU considerations.

## 6. Versioning, extension policy and interoperability

* Wire major `0x01` is **reserved for this candidate** until approval. Existing Rust `PROTOCOL_MAJOR_VERSION = 0` must remain unchanged during M0.3.
* Unsupported major, type or flags cause deterministic rejection without detailed unauthenticated error disclosure.
* No opportunistic downgrade to insecure profiles; alternative QUIC/TLS modes need separate specifications.
* Application version, crate semver and wire major are independent.
* Never publish `v1 interoperable` until canonical field encodings, Noise transcript and crypto vectors match an independent second implementation.

## 7. Review gates (blocking M0.4/M0.5)

1. Freeze CID assignment/bootstrap, handshake payloads, lengths and exact Noise prologue/transcript.
2. Validate Noise IK transcript, Split key use, AEAD AD/nonce and CONFIRM with independent vectors.
3. Specify and test rate-limited replay cache for INITIAL, half-open session limits and amplification budget.
4. Prove counter exhaustion and fresh-session reconnect behavior under crashes and retransmission.
5. Implement canonical positive/negative parser vectors before approving packet codec.
6. Review UDP pacing/MTU, congestion and server resource exhaustion limits.

References: https://noiseprotocol.org/noise.html ; https://www.rfc-editor.org/rfc/rfc8439 ; https://www.rfc-editor.org/rfc/rfc8085 ; https://www.rfc-editor.org/rfc/rfc8899

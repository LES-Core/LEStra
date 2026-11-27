# LEStra Cryptographic Implementation

Status: experimental M0.5 implementation.

## Implemented

- Authenticated Noise IK handshake.
- Pinned server identity and authorized client static keys.
- Directional Noise transport cipher states.
- Full-header AEAD associated data.
- Monotonic directional packet counters.
- Strict packet number exhaustion policy.
- Fixed-size 1024-bit receive replay window.
- Authenticated CONFIRM and READY.
- Bounded cached READY retransmission.
- Unreliable encrypted application datagrams.
- Authenticated and local session closure.

## Cryptographic backend

LEStra uses Snow from the upstream repository, pinned to a specific Git revision providing explicit associated data support.

The production implementation does not export raw Noise Split keys or enable the risky-raw-split feature.

## Session invariants

- Application data is unavailable before authenticated session establishment.
- Outgoing packet numbers are assigned internally.
- Replay state is updated only after successful authentication.
- Invalid network packets do not expose unauthenticated plaintext.
- Retransmitted handshake packets reuse cached ciphertext.
- Closed sessions cannot protect or accept new packets.
- Reconnection requires fresh Noise session keys.

## Verification

The verification strategy includes:

- Independent deterministic protocol vectors.
- Noise handshake integration tests.
- Packet protection and counter boundary tests.
- Replay window tests.
- Public session API integration tests.
- Operating system UDP loopback tests.
- Simulated handshake packet loss and recovery.
- Cross-session packet rejection.

## Remaining security requirements

- Independent cryptographic and protocol review.
- Production parser and session fuzzing.
- Key material lifetime and zeroization review.
- Bounded handshake admission and session tables.
- CID collision and retirement policies.
- Per-source rate limiting and amplification accounting.
- Session deadlines and retransmission scheduling.
- Congestion response and pacing.
- Path MTU handling.
- Key provisioning, rotation and revocation.
- Real network stress and concurrency testing.

The implementation is experimental. Passing tests do not establish production security or approve the stable v1 wire format.

The public protocol major version remains 0.

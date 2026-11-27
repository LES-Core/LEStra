# LEStra Native UDP - Congestion Feedback and Control

Status: PROPOSED / REVIEW DRAFT

Milestone: M1.6.4

This document proposes an experimental congestion-controlled
native UDP profile. It does not modify the currently implemented
wire profile or authorize production deployment.

## 1. Goals

- Preserve unreliable and unordered application datagrams.
- Detect probable network loss using authenticated feedback.
- Measure round-trip time using a monotonic local clock.
- Limit outstanding DATA bytes and transmission rate.
- Bound memory usage independently of peer-provided packet numbers.
- Remain independent of a particular async runtime.
- Avoid automatic retransmission of application DATA.

Reliable streams, flow control, ECN, path migration, bandwidth
probing and BBR are outside the initial implementation scope.

## 2. Experimental wire profile

The proposed profile uses:

- Wire major: 0x02.
- Noise pattern: Noise_IK_25519_ChaChaPoly_SHA256.
- Noise prologue: exact ASCII "LEStra/native-udp/v2".
- ACK packet type: 0x07.
- Maximum UDP payload: 1200 bytes.

The existing 26-byte envelope remains unchanged.

The experimental profile must be selected explicitly by both
endpoints. Automatic downgrade or unauthenticated negotiation
is forbidden.

The public PROTOCOL_MAJOR_VERSION constant remains zero
until formal approval.

Existing deterministic vectors remain associated with the
original wire profile. New vectors must be generated separately.

## 3. ACK packet

ACK is a protected transport control packet.

Its plaintext has the following fixed layout:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | largest_acked |
| 8 | 128 | bitmap |

largest_acked is an unsigned big-endian 64-bit integer.

The ACK plaintext length is exactly 136 bytes.
The protected body length is exactly 152 bytes.
The complete UDP payload length is exactly 178 bytes.

The ACK header must contain:

- The selected wire major.
- Packet type 0x07.
- Zero flags.
- The peer's nonzero receive CID.
- A fresh packet number in 1..2^32-1.
- Body length 152.

The entire header is authenticated as AEAD associated data.

ACK consumes the same directional packet-number space
as DATA and CLOSE. It does not introduce new traffic keys,
nonce spaces or cryptographic primitives.

## 4. Bitmap semantics

The bitmap describes DATA packet numbers only.

For bit index i in 0..1023:

    packet_number = largest_acked - i

Within each bitmap byte, the least significant bit
represents the lowest bit index.

Bit 0 must be set.

largest_acked must be nonzero and below 2^32.

Bits corresponding to packet number zero or an arithmetic
underflow must be zero.

A set bit indicates that the corresponding DATA packet was
successfully authenticated and committed to the replay window.

An unset bit is not definitive proof of network loss.

The receiver maintains a separate bounded DATA acknowledgment
bitmap. Non-DATA packets are not acknowledged by this bitmap.

The existing replay window continues to cover all protected
packets, including ACK.

## 5. ACK generation

ACK is permitted only after local session establishment.

The responder must successfully submit READY to UDP
before sending ACK or application DATA.

Generate feedback after:

- Two newly authenticated DATA packets; or
- 25 milliseconds after the first unacknowledged
  receive-side DATA event.

The first applicable condition schedules an ACK.

The receiver may repeat the latest feedback snapshot
at most twice, approximately 100 and 200 milliseconds
after the first successful transmission of that snapshot.

Each ACK transmission uses a fresh packet number
and fresh authenticated encryption.

New DATA supersedes an older pending snapshot.

Feedback repeats are bounded and must not extend
the session lifetime by themselves.

ACK is not acknowledgment-eliciting.

Receiving ACK must never trigger ACK generation.

Rejected packets, duplicate DATA and invalid AEAD tags
must not trigger new feedback.

Feedback transmission is subject to independent bounded
packet and byte budgets, plus aggregate socket limits.

Initial candidate feedback limits:

- 100 ACK packets per second per session.
- Maximum burst of two ACK packets.
- No more than one ACK attempt per 10 milliseconds
  after local socket backpressure.

The 25-millisecond scheduling target does not override
rate limits or socket availability.

## 6. Sender history

Each sending direction maintains a bounded history
of outstanding DATA packets.

Each entry records:

- Packet number.
- UDP payload length.
- Monotonic socket submission timestamp.
- Whether congestion-window growth was eligible
  when the packet was submitted.

The initial maximum history capacity is 1024 DATA entries.

The implementation must not allocate memory proportional
to the numerical value of a packet number.

The sender must reserve history capacity before encrypting
a new DATA packet.

A DATA packet becomes in flight only after successful
submission to the operating system.

Queued ciphertext is not yet in flight.

Local queue expiration and failed socket submissions
must not be classified as measured network loss.

Reserved history capacity must be released when a queued
packet is discarded.

History exhaustion applies backpressure before assigning
another DATA packet number.

ACK and CLOSE remain independent of DATA history capacity.

## 7. ACK processing

An ACK must pass:

1. Canonical framing validation.
2. Source endpoint and CID validation.
3. Session state validation.
4. Replay candidate validation.
5. AEAD authentication.
6. Replay commit.
7. ACK plaintext semantic validation.

Invalid ACK plaintext must not modify congestion state,
sender history, RTT estimates or session activity.

Feedback with largest_acked greater than the highest
successfully submitted DATA packet number is invalid.

Only matching outstanding DATA history entries may
produce acknowledgment credit.

Unknown, already retired or locally discarded packet
numbers must not create acknowledgment credit.

An outstanding entry may be acknowledged at most once,
regardless of how many ACK snapshots mention it.

Acknowledgment releases bytes in flight and history capacity.

ACK processing must have bounded computational complexity
and must not iterate over arbitrary packet-number ranges.

An authenticated peer is not necessarily an honest peer.
AEAD does not prove that acknowledged DATA was actually
received. Local transmission ceilings remain mandatory.

## 8. RTT estimation

RTT is sampled using the newest newly acknowledged
outstanding DATA packet in a valid feedback snapshot.

    sample = acknowledgment_received_at - submitted_at

Use a monotonic local clock.

Do not sample packets that were never submitted to UDP,
already declared lost or previously acknowledged.

The initial implementation does not encode ACK delay.

Consequently, RTT samples include receiver feedback delay,
local scheduling delay and network delay.

No untrusted peer-provided delay is subtracted.

Maintain:

- latest_rtt
- min_rtt
- smoothed_rtt
- rtt_variance

For the first sample:

    smoothed_rtt = sample
    rtt_variance = sample / 2

For subsequent samples:

    rtt_variance =
        3/4 * rtt_variance
        + 1/4 * abs(smoothed_rtt - sample)

    smoothed_rtt =
        7/8 * smoothed_rtt
        + 1/8 * sample

Use the previous smoothed_rtt when updating variance.

All calculations must be bounded and overflow-safe.

The initial RTT estimate is 333 milliseconds.

## 9. Loss detection

Only outstanding DATA packets successfully submitted
to UDP are eligible for network loss classification.

A DATA packet may be declared lost if either:

- At least three distinct, later DATA packets have
  been acknowledged; or
- A later DATA packet has been acknowledged and
  the time threshold has elapsed.

The initial time threshold is:

    max(
        9/8 * max(latest_rtt, smoothed_rtt),
        1 millisecond
    )

The packet threshold counts acknowledged DATA packets,
not the numerical distance between packet numbers.

ACK packets and locally skipped packet numbers must not
artificially increase the loss threshold.

Missing bits in a single ACK bitmap must not immediately
declare packets lost.

A loss decision releases the corresponding bytes in flight
and history entry.

Late acknowledgments for retired entries must not release
the same bytes again or increase the congestion window.

Application DATA is never automatically retransmitted.

## 10. Congestion controller

The first controller uses a conservative NewReno-inspired
window-based algorithm.

Maintain per sending direction:

- congestion_window
- bytes_in_flight
- slow_start_threshold
- recovery_end
- additive_increase_credit
- queued_bytes

Initial candidate values:

| Parameter | Value |
|---|---:|
| Maximum datagram size | 1200 bytes |
| Initial congestion window | 4800 bytes |
| Minimum congestion window | 2400 bytes |
| Maximum congestion window | 1048576 bytes |
| Multiplicative decrease | 0.5 |

The initial congestion window is a LEStra test policy,
not the QUIC default.

### 10.1. Send admission

New DATA is permitted only when:

    bytes_in_flight + queued_bytes + wire_bytes
        <= congestion_window

History capacity, configured transmission ceilings
and pacing must also permit transmission.

If the current window shrinks below outstanding bytes,
stop accepting new DATA until sufficient credit is released.

### 10.2. Slow start

While congestion_window is below slow_start_threshold,
eligible newly acknowledged DATA increases the window
by its acknowledged UDP payload length.

Window growth is disabled for application-limited
or administratively rate-limited transmissions.

### 10.3. Congestion avoidance

For eligible newly acknowledged DATA:

    increase =
        max_datagram_size * acknowledged_bytes
        / congestion_window

Preserve fractional additive-increase credit.

The increase is approximately one maximum-size datagram
per round trip when the congestion window is fully utilized.

All increases are capped by the configured maximum window.

### 10.4. Recovery

On the first loss of a new recovery episode:

    congestion_window =
        max(minimum_window, congestion_window / 2)

    slow_start_threshold = congestion_window

    recovery_end =
        highest successfully submitted DATA packet number

Reset additive-increase credit.

Further losses of packets submitted before or at
recovery_end must not reduce the window again.

Acknowledgments for packets at or below recovery_end
must not increase the congestion window.

### 10.5. Idle restart

After at least one second without outstanding DATA,
the next transmission must restart with no more than
the initial congestion window.

Previously accumulated pacing credit must be clamped
to the restart burst limit.

## 11. Pacing

The congestion-controlled DATA rate is bounded by:

    adaptive_rate =
        congestion_window / max(smoothed_rtt, 1 millisecond)

The effective rate is the minimum of:

- adaptive_rate
- configured per-session transmission ceiling
- available aggregate transmission budget

The initial DATA burst is limited to two maximum-size
datagrams or the configured smaller burst.

Rate and burst reductions must clamp accumulated credits.

Pacing applies to actual socket submission attempts,
including attempts to flush queued ciphertext.

Failed submission attempts may consume pacing credit
conservatively.

The queued DATA reservation must not be charged twice
against the congestion window.

Before flushing a queued packet, revalidate session
lifetime, history reservation and congestion-window budget.

If necessary, delay or discard the queued packet.

Never regenerate queued ciphertext with a reused nonce.

## 12. Feedback silence

Feedback silence is not proof of a specific packet loss.

While DATA is outstanding, maintain a no-progress timer.

The initial no-progress limit is derived from:

    max(
        3 seconds,
        3 * (
            smoothed_rtt
            + max(4 * rtt_variance, 1 millisecond)
        )
    )

The limit is capped at 30 seconds.

Capture the deadline when outstanding DATA first appears.
Only newly acknowledged DATA may restart the timer.

Sending more DATA, receiving duplicate ACKs or receiving
invalid packets must not extend the deadline.

When the deadline expires:

- Stop transmitting DATA.
- Retire the cryptographic session.
- Release outstanding history and queued ciphertext.
- Report a feedback timeout to the application.

A fresh handshake is required before further transmission.

This initial profile does not generate synthetic DATA
probes, implement PTO probing or automatically reconnect.

## 13. Session activity

Authenticated fresh DATA continues to refresh idle activity.

For this experimental profile, an authenticated ACK that
newly acknowledges outstanding DATA may also refresh
idle activity.

This is an intentional change from the original profile.

Duplicate feedback, unknown acknowledgments, socket
submission and local queue activity do not refresh it.

The absolute session lifetime is never extended.

## 14. Resource and security requirements

- Bound DATA history per session and globally.
- Bound ACK generation and processing costs.
- Preserve the existing 1024-packet replay window.
- Preserve directional packet-number exhaustion rules.
- Use fresh traffic keys after reconnect.
- Prevent integer overflow and double accounting.
- Preserve endpoint binding.
- Release all feedback state on session removal.
- Enforce aggregate UDP transmission limits.
- Do not interpret socket backpressure as network loss.
- Do not retransmit application DATA.

Separate congestion controllers must not be used to bypass
aggregate destination or path-level traffic limits.

Control traffic remains subject to bounded scheduling and
aggregate transmission policy. ACK must not create an
unlimited exception to congestion control.

## 15. Required verification

### Wire and cryptography

- Canonical ACK encoding and decoding.
- Exact bitmap bit ordering.
- Invalid lengths and packet-number boundaries.
- Header and ciphertext tampering.
- Wrong session, endpoint and destination CID.
- Duplicate ACK replay rejection.
- No ACK before establishment.
- No cross-profile handshake acceptance.

### Feedback and accounting

- Correct acknowledgment of reordered DATA.
- ACK of already retired DATA.
- ACK claiming locally unsent packet numbers.
- Skipped packet numbers between submitted DATA.
- No double release of bytes in flight.
- Bounded history exhaustion.
- Queued DATA is not counted as submitted DATA.
- Queue expiration does not report network loss.
- No ACK-of-ACK feedback loop.

### Congestion behavior

- RTT estimator initialization and updates.
- Packet-threshold loss detection.
- Time-threshold loss detection.
- Slow start and additive increase.
- One multiplicative decrease per recovery episode.
- Minimum and maximum window enforcement.
- Application-limited growth suppression.
- Pacing after congestion-window reduction.
- Feedback silence and session retirement.
- Idle restart.
- Loss, delay and reordering simulations.
- Multiple competing sessions.

## 16. Implementation sequence

M1.6.5:
- Experimental wire profile and ACK codec.
- Independent deterministic vectors.

M1.6.6:
- Protected ACK transmission and reception.
- Bounded acknowledgment bitmap.
- Sender history and RTT estimator.

M1.6.7:
- Congestion window and loss detection.
- Adaptive pacing.
- Feedback timeout and lifecycle integration.

M1.7:
- Deterministic network fault simulation.
- Real network integration and load tests.
- Congestion fairness evaluation.

M1.8:
- Performance and resource benchmarks.

## 17. Approval gates

The proposal does not claim RFC 9002 compliance.

NewReno-related behavior is adapted to unreliable LEStra
datagrams and must be independently evaluated.

Production deployment remains blocked on:

- Independent security review.
- Congestion fairness and stability testing.
- Aggregate traffic control.
- Bounded memory and CPU measurements.
- Path MTU and deployment validation.
- Formal wire-profile approval.

## References

- RFC 8085: UDP Usage Guidelines
  https://www.rfc-editor.org/rfc/rfc8085

- RFC 9002: QUIC Loss Detection and Congestion Control
  https://www.rfc-editor.org/rfc/rfc9002

- RFC 5681: TCP Congestion Control
  https://www.rfc-editor.org/rfc/rfc5681

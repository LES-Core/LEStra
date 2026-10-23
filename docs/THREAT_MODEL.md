# LEStra Threat Model (M0.2)

Status: **Draft, preliminary, for initial native UDP client–server mode.** This is not a security audit or claim of production readiness.

## Assets

- Confidentiality and integrity of application/IP payloads.
- Authenticity of server and authorized client identities.
- Freshness of session traffic and uniqueness of nonces.
- Traffic/session keys and locally stored identity keys.
- Availability of server CPU, memory and network resources.
- Explicit security policy for transport selection and fallback.

## Trust boundaries

1. **Application → SDK:** Application-supplied configuration and payloads are untrusted until validated. Applications must provide trusted peer identities.
2. **SDK → network:** The network and all received packets are attacker-controlled.
3. **Client → server:** Both endpoints must authenticate independently. Successful authentication is not the same as authorization.
4. **Protocol → tunnel adapter:** IP forwarding, routes, DNS and kill switch policy are outside the core protocol.
5. **Transport profile switch:** No automatic fallback may silently weaken an application's required security guarantees.

## Adversary capabilities

Assume an active on-path adversary can observe metadata, drop, duplicate, delay, reorder, replay, inject or alter packets, spoof source IPs, and block individual ports, endpoints or recognizable protocols. An attacker can initiate many concurrent handshakes and send malformed input. A compromised endpoint, stolen private key or compromised operating system is **out of scope** for confidentiality guarantees of that endpoint.

## Security objectives

| Objective | Proposed control | Verification |
|---|---|---|
| Peer authenticity | Authenticated Noise handshake; pinned server public key; authorized client keys | Invalid-peer, unknown-key and key-mismatch tests |
| Payload secrecy/integrity | Reviewed AEAD with transcript-bound session keys | Known-answer vectors, bit-flip and ciphertext-rejection tests |
| Replay resistance | Monotonic counters and bounded sliding receive window scoped to key epoch | Duplicate, reordered and old-packet tests |
| Nonce safety | Separate per-direction key material and unique nonces per epoch | State-machine tests, key-exhaustion tests |
| Downgrade safety | Authentication of negotiated version, capabilities and profile | Tampered negotiation tests |
| Resource safety | Bounded parse sizes, connection limits, rate limiting, anti-amplification design | Fuzzing, handshake flood simulations |
| Parser robustness | No panics or unbounded allocations on adversarial input | Coverage-guided fuzzing and property tests |
| Key lifecycle | Secure storage guidance, explicit rotation/revocation policy | Reconnect, revoked-key and rotation tests |

## Residual risks / non-guarantees

- Encryption does not hide endpoint IPs, timestamps, packet sizes, traffic rates, or necessarily the protocol fingerprint.
- DPI resistance is probabilistic and deployment dependent. Blocking all UDP defeats UDP-based profiles; a fallback may also be filtered.
- Traffic-flow confidentiality is not guaranteed; padding and alternative profiles impose bandwidth/latency costs.
- Key pinning requires trusted out-of-band key provisioning. First-use acceptance without verification is a weaker policy.
- Endpoint compromise can expose identity keys and plaintext.
- A VPN mode does not automatically prevent DNS leaks or enforce kill switches: those are application/OS-level responsibilities.
- Server operators may observe destination metadata and traffic at the egress point; this is not an anonymity network.

## Required security review gates

- **Before M0.3 freeze:** documented handshake pattern, authenticated negotiation and nonce/rekey scheme reviewed against the Noise specification.
- **Before M0.5 merge:** interop vectors, negative tests, fuzz harness and explicit parsing limits.
- **Before public production claims:** independent security assessment and deployment-hardening guide.

## Incident response

Follow repository `SECURITY.md` for private vulnerability reporting. Avoid publishing exploit details until maintainers have assessed and coordinated a fix.

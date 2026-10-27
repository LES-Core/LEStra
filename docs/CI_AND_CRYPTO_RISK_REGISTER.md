# LEStra CI & cryptographic readiness review — 2026-10-26

**Scope:** repository `LES-Core/LEStra` after Dependabot PR #5 and experimental Noise IK PR #4. **Not a security audit or wire v1 freeze.** This register separates proof of test compatibility from requirements for a production session.

## Verified main snapshot

- `main`: `d70e346af302daeba8ea5be584306e2124d97357`, merge commit for PR #5 (merged 2026-10-25 20:52:53 UTC).
- PR #4 experimental `lestra-crypto` Noise IK handshake merged 2026-10-24 15:04:12 UTC as `c96f4d5db7e3506e0a08435b03eebd6a5af41302`.
- PR #5 changed **only** `tools/requirements-vectors.txt`: `cryptography==46.0.4` to `cryptography==50.0.0`. It did not update production Rust dependencies or the committed reference vectors.
- PR #5 head `391514f1b8eee45806f7103a7520f7bbaa8dfb96`:
  - [Protocol vectors](https://github.com/LES-Core/LEStra/actions/runs/40127403089) passed: installed `cryptography==50.0.0`; `generate_vectors.py --check` matched the committed fixture exactly; 4 Python vector tests, 15 handshake-state model tests, 11 network-fault model tests, and 21 independent Rust tests passed.
  - [LEStra CI](https://github.com/LES-Core/LEStra/actions/runs/40127403085) concluded success, with `Rust formatting and Clippy` and `Test / ${{ matrix.os }}` **skipped**. The detected `RUST=false` status is correct for this Python-only dependency change; `lestra-ci-required` validated that routing, **not** the production Rust implementation.
- [Protocol vectors push on merged main](https://github.com/LES-Core/LEStra/actions/runs/40232843001) passed for `d70e346a`. No `LEStra CI` push run was created for that commit because its workflow `push.paths` does not match the changed requirements file.
- No open PRs were found at the time of this review (before the review PR itself).

## Actual ruleset and CI policy gap

Active [`main-ruleset`](https://github.com/LES-Core/LEStra/rules/25723846) (`required_status_checks`) currently requires **only** `lestra-ci-required`. In particular, **Protocol vectors is not enforced at merge time**, regardless of whether it ran or failed. GitHub's separate branch `protected` field is not a sufficient substitute for examining the active repository ruleset.

Before this review, `.github/workflows/protocol-vectors.yml` used workflow-level `pull_request.paths`. That is inappropriate for a status which will become required: a nonmatching PR would have no check run and could remain blocked with a missing required status. It also omitted `tools/test_handshake_network.py` from its push/PR filters.

**CI change proposed in this review PR:**
1. Run both Protocol vectors jobs on *all* PRs targeting `main` (stable, always-present check contexts).
2. Keep event path filtering for relevant pushes, adding `tools/test_handshake_network.py` explicitly.
3. Add a single `lestra-protocol-vectors-required` job with `if: always()` that succeeds only when **both** the Python and Rust reference jobs succeed.

**Manual repository setting still required:** after the new job exists and reports success at least once, an authorized maintainer must add `lestra-protocol-vectors-required` to the active `main-ruleset`'s required status checks, retaining `lestra-ci-required`. This PR **cannot** itself enforce repository ruleset settings.

## Mandatory gate by changed files

| Scope | Required verification | Interpretation |
|---|---|---|
| `tools/requirements-vectors.txt` | `lestra-protocol-vectors-required` — pip installation, byte-for-byte `generate_vectors.py --check`, Python vector/model tests, isolated Rust Noise/AEAD tests | A generator dependency change must not silently alter frozen reference bytes or their independently verified properties |
| `tools/generate_vectors.py`, `tools/test_vectors.py`, `tools/test_handshake_state.py`, `tools/test_handshake_network.py`, `spec/v1/**`, `tools/protocol-vectors-rust/**` | Same protocol gate | All reference-fixture and model changes require cross-checking |
| `crates/**`, workspace Cargo files, Rust tooling/CI | `lestra-ci-required`: rustfmt, Clippy and Ubuntu/Windows/macOS tests; **plus** the always-running protocol gate on PRs | These checks do not replace security review |
| Python-only dependency change without Rust changes | Main Rust matrix may legitimately be skipped; protocol gate must still be green | Do **not** interpret `lestra-ci-required` success as Rust tests executed |

For a new Python *major-version upgrade* or changed supported deployment platform, additionally validate compatibility outside the Ubuntu 24.04 / Python 3.12 CI baseline (at least each intended Python/OS combination). Verify supported wheel availability and the transitive dependencies before expanding support claims.

## Residual CI and supply-chain risks

| ID | Severity | Finding / exit criterion |
|---|---|---|
| CI-01 | **High** | Active ruleset lacks the protocol gate. **Exit:** maintainer adds `lestra-protocol-vectors-required` to required contexts, verifies a failing protocol job blocks a test PR and a passing job unblocks it. |
| CI-02 | Medium | Existing Python reference CI tests only Ubuntu/Python 3.12; `cryptography` transitive wheels and `cffi`/other dependencies are not fully pinned. **Exit:** explicitly document supported OS/Python combinations and test them; adopt a reviewed lock/hash strategy if reproducible supply-chain resolution is needed. |
| CI-03 | Medium | Independent verifier consumes the **committed** vectors; it does not regenerate via the changed Python dependency. Independence is meaningful only together with the generator equality check. **Exit:** require *both* jobs, never one alone. |
| CI-04 | Medium | Tests are fixed-vector and bounded-model tests, not unbounded fuzzing, cross-implementation network interoperability or production performance tests. **Exit:** exercise production parser, authenticated sessions and pathological input/load separately. |
| CI-05 | Low | On push, `LEStra CI` is intentionally path-filtered and will not run for requirements-only merges. **Exit:** maintain the dedicated protocol push trigger and do not misreport a nonexistent Rust CI run. |

## Unresolved Noise IK / transport security risks

| ID | Severity | Blocker before full secure-session or production claims |
|---|---|---|
| CRYPTO-01 | **High** | `lestra-crypto` presently authenticates the two Noise IK handshake messages only. **CONFIRM, READY, encrypted DATA and CLOSE are not implemented** in production. No application delivery should be enabled. |
| CRYPTO-02 | **High** | LEStra requires the **entire 26-byte header as AEAD AAD**. Standard `snow` transport helpers are not an acceptable replacement unless that requirement is met. Design/review explicit-AAD-capable key and cipher integration without enabling unsafe raw-key export in ordinary production APIs. |
| CRYPTO-03 | **High** | Enforce per-direction nonce uniqueness, a strict `2^32` protected-packet limit, atomic replay-window recheck/commit, fresh keys after crash/reconnect and byte-identical retransmissions. Reference replay tests are not production concurrency guarantees. |
| CRYPTO-04 | **High** | Implement real rate/CPU/half-open-state quotas, per-source amplification accounting (≤3:1 pre-validation), CID collision/retirement handling and bounded handshake/retry caches. Current simulation coverage does not establish DoS safety. |
| CRYPTO-05 | Medium | Pinned server identity and allowlisted client keys exist in the experimental handshake, but durable provisioning, rotation, revocation, ACL refresh and identity-key isolation require a complete operational design. Public deterministic vector private keys are **test-only**. |
| CRYPTO-06 | Medium | Source/address binding and replay logic require integration across real UDP sockets, NAT changes, race conditions, timer eviction, pacing/congestion control and PMTU. Test-only loopback and virtual-time models do not prove real deployments safe. |
| CRYPTO-07 | Medium | Protocol wire v1 is still a **review draft** and `lestra-core::PROTOCOL_MAJOR_VERSION` must remain `0` until explicit wire/security sign-off. A green CI does not constitute that sign-off. |

## Acceptance checklist for next LEStra phase

- [ ] Merge CI review only after `lestra-protocol-vectors-required` and `lestra-ci-required` report success on its head.
- [ ] Authorize and configure both contexts in the active `main-ruleset`; validate the fail-closed branch rule.
- [ ] Keep `cryptography==50.0.0` reference-vectors immutable unless a reviewed update intentionally changes them, with corresponding regenerated fixtures and independent verification.
- [ ] Design and test explicit-header-AAD AEAD before exposing secure transport or DATA APIs.
- [ ] Implement and test authenticated CONFIRM/READY, replay-safe data-plane counters, resource budgets, and reconnect behavior.
- [ ] Obtain independent cryptographic/protocol review and interoperability evidence before declaring stable native UDP v1.

**Disposition:** Dependabot PR #5 merge is supported by its verified reference tests; the current *governance enforcement* and production secure-session implementation are incomplete. Do not merge security requirements into an unrelated `cryptography` version bump after the fact.

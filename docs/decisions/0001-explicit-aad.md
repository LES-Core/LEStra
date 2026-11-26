# ADR 0001: Explicit AAD crypto backend

Status: Proposed

## Context

LEStra native UDP requires authentication of the complete
26-byte packet header as AEAD associated data.

Snow 0.10.0 does not expose explicit associated data through
its public stateless transport API.

## Proposed approach

Retain Noise_IK_25519_ChaChaPoly_SHA256 and evaluate a minimal
Snow extension providing explicit AAD support.

## Requirements

- Preserve the existing wire format.
- Preserve Noise Split key derivation.
- Preserve directional key separation.
- Support explicit packet-number nonces.
- Authenticate the entire packet header.
- Do not expose raw traffic keys.
- Do not implement new cryptographic primitives.
- Preserve compatibility with committed protocol vectors.

## Alternatives

- Raw Split key extraction.
- Alternative Noise implementation.
- A revised wire protocol.

## Validation

- Exact compatibility with existing protocol vectors.
- Header tampering rejection.
- Ciphertext and tag tampering rejection.
- Directional key separation.
- No public raw-key export.

## Limitations

This decision does not establish production security.
Replay protection, nonce lifecycle, session state and
independent security review remain required.

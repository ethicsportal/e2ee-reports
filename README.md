# e2ee-reports

End-to-end encrypted reporting channel for whistleblower software under EU Directive 2019/1937.

A free software library and protocol specification. Reports are encrypted on the reporter's device to public keys held by designated case handlers; the operator stores only ciphertext and never holds keys. Designed for asynchronous case handling — reports often need follow-up across weeks — with forward secrecy across sessions and unlinkable acknowledgement receipts.

## Threat model

In scope:

- Operator-side insiders with full database access
- Hosting providers with snapshot access
- State subpoenas served on the operator
- Operators acting under coercion (gag orders, executive interference)

Out of scope:

- Reporter-endpoint compromise
- Traffic analysis (a Tor-shaped problem, addressed at a different layer)
- Recipient compromise after legitimate decryption

## Protocol

- Long-term recipient keypair per channel (X25519). Private keys held in hardware-backed storage by case handlers (YubiKey-class devices).
- Per-report ephemeral keypair on the reporter side. Hybrid encryption with ChaCha20-Poly1305 for the payload.
- Ratcheted key derivation for thread continuation; forward-secret across asynchronous follow-ups that may span weeks of inactivity.
- Blind acknowledgement tokens so the operator cannot link receipts to the originating session.

The cryptographic primitives are well-studied. The novelty is the protocol shape: one-to-many ingestion, persistent server-side thread state, weeks-long asynchronous follow-up, unlinkable receipts. Existing E2EE work (Signal Protocol, MLS / RFC 9420, age) does not fit this shape.

## Deliverables

1. Protocol specification (IETF-style document, public review)
2. Reference implementation in Rust (`e2ee-reports`)
3. Rails integration adapter (`e2ee-reports-rails`)
4. Community security review with public response document
5. Implementer's guide and reference deployment

## License

AGPL-3.0. Modifications served as a network service must be published.

## Status

In planning. NGI Zero Commons Fund proposal under preparation for the 1 June 2026 deadline. Implementation begins after grant agreement is signed.

## Contact

yaroslav@ethicsportal.eu

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

Prototype reference implementation in Rust. It covers the core of the protocol; several properties in the threat model are still open.

Implemented:

- Report envelope: a fresh X25519 ephemeral key per report, HKDF-SHA256, ChaCha20-Poly1305, with the version and both public keys bound as associated data. Low-order keys are refused.
- Follow-up threads: one HKDF chain per direction and a fresh key per message. State captured later cannot decrypt earlier messages (forward secrecy). Messages must be read in order.
- Thread state that can be saved and resumed weeks later.
- Known-answer test vectors in [test-vectors/v1.json](test-vectors/v1.json). The X25519 layer matches the published public key for the `00..1f` test secret.
- CI: formatting, clippy and tests on every push.

Not yet:

- A Diffie-Hellman ratchet. The symmetric chains do not recover after a compromise.
- Unlinkable acknowledgement tokens.
- Hardware-backed recipient keys. `ChannelSecret` is plain bytes in memory.
- Authentic distribution of channel public keys.
- A server component, the Rails adapter, and the self-hosting package.
- External security review. Do not use this to protect real reports yet.

An NLnet NGI grant application was submitted in June 2026 to fund the full specification and the open items above. See [docs/protocol.md](docs/protocol.md) and [docs/threat-model.md](docs/threat-model.md) for the design, and [SECURITY.md](SECURITY.md) for how to report findings.

## Usage

```rust
use e2ee_reports::{open, seal, ChannelSecret};
use rand_core::OsRng;

// Case handler, once per channel.
let channel = ChannelSecret::generate(&mut OsRng);

// Reporter.
let sealed = seal(&mut OsRng, &channel.public_key(), b"report text")?;
let mut reporter_thread = sealed.thread; // keep this to read replies later
// upload sealed.envelope.to_bytes()

// Case handler.
let opened = open(&channel, &sealed.envelope)?;
let mut handler_thread = opened.thread;
let reply = handler_thread.encrypt(b"thank you, one question")?;
assert_eq!(reporter_thread.decrypt(&reply)?, b"thank you, one question");
```

## Contact

yaro@ethicsportal.eu

# Protocol

A working sketch of the `e2ee-reports` protocol. This is design intent, not a frozen specification; the formal specification is the first deliverable and will supersede this document.

## Why existing protocols do not fit

The cryptographic primitives are conventional and well-studied. The difficulty is the shape of the problem, which existing end-to-end encryption work does not match:

- **Signal Protocol / libsignal** assumes synchronous messaging between parties who share a contact list. A reporting channel has neither: ingestion is one-to-many, the reporter is anonymous, and exchanges are asynchronous.
- **MLS (RFC 9420)** is group messaging with shared, evolving group key state. A reporting channel is not a group; it is many independent reporters submitting to a small set of recipients.
- **age** is file encryption. It has no thread, no acknowledgement, and no forward secrecy across a continuing exchange.

The novel element is the protocol shape: one-to-many ingestion, persistent server-side thread state, follow-up that can span weeks of inactivity, and acknowledgement receipts the operator cannot link to a reporter.

## Roles

- **Reporter.** Anonymous or pseudonymous. Holds no long-term account or key.
- **Channel.** A reporting endpoint operated by an organization. Has a long-term recipient keypair.
- **Recipient (case handler).** Holds the channel private key in hardware-backed storage. There may be more than one.
- **Server.** Stores and routes ciphertext. Untrusted with plaintext.

## Keys

- Each channel has a long-term recipient keypair (X25519). The public key is published to reporters; the private key never leaves hardware-backed storage held by recipients.
- Each report begins with a fresh ephemeral keypair generated on the reporter's device.
- Thread continuation uses a ratcheted key derivation so that each follow-up message has fresh key material.

## Submitting a report

1. The reporter obtains the channel public key and verifies its authenticity.
2. The reporter device generates an ephemeral keypair and derives a shared secret with the channel public key.
3. The report payload is encrypted with ChaCha20-Poly1305 under a key derived from that shared secret.
4. The device sends ciphertext, the ephemeral public key, the wrapped content key, and an opaque thread token.
5. The server stores these without the ability to decrypt. It learns only that some report exists on some channel.

## Follow-up over time

Reports frequently need clarification, and exchanges may resume after long gaps. The thread uses a ratchet so that each message exchange advances the key state and earlier messages stay protected even if later key material is exposed. The construction must tolerate weeks of inactivity without breaking thread continuity, which is where standard ratchets that assume frequent cadence need adaptation.

## Acknowledgement

The reporter receives a blind acknowledgement token tied to the thread but unlinkable by the operator to the originating session. This lets the reporter confirm receipt and later retrieve replies without revealing to the operator which submission was theirs.

## Open design questions

These are the substantive problems the specification and reference implementation must resolve:

1. A ratchet that advances per message exchange yet survives weeks of inactivity.
2. Hardware-backed recipient keys that non-engineers (HR, compliance, NGO staff) can actually use, without a PGP-style usability cliff.
3. An acknowledgement-token construction that is verifiable by the reporter and unlinkable by the operator.
4. Server-side triage for case handlers without leaking content, most likely by indexing client-side after recipient decryption and documenting that as the integration pattern.

## Deliverables that build on this

1. Protocol specification, IETF-style, for public review.
2. Rust reference implementation (`e2ee-reports`) with known-answer test vectors, continuous integration, and a fuzzing harness.
3. Rails integration adapter (`e2ee-reports-rails`).
4. A self-hostable reference deployment that can be run with no central operator.

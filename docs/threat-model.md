# Threat model

This document states what `e2ee-reports` defends against, what it explicitly does not, and the security properties the protocol must provide. It is the reference point for the protocol design and for any security review.

## Setting

EU Directive 2019/1937 obliges employers to keep the identity of a reporting person confidential. In practice almost every reporting channel in use today stores reports in a database the operator can read. "Encryption at rest" protects against a stolen disk or a leaked backup; it does nothing against the operator itself, an insider with database access, or a legal order served on the host. The confidentiality obligation and the deployed reality are therefore far apart.

`e2ee-reports` closes that gap: the server holds ciphertext only and never holds the keys that decrypt it.

## Assets to protect

1. The content of a report.
2. The identity of the reporting person, beyond whatever they choose to disclose.
3. The link between a reporting person and any specific report or thread.
4. Follow-up correspondence on a report, which may continue for weeks.

## Adversaries in scope

1. **Operator-side insider** with full application and database access (DBA, sysadmin, a leaked or exfiltrated backup).
2. **Hosting or cloud provider** able to snapshot storage and memory.
3. **State authority** serving a subpoena or equivalent compelled-disclosure order on the operator or host.
4. **Coerced operator** acting under a gag order, NDA, or executive pressure.

The unifying assumption: the party running the server is not trusted with plaintext. Defending against the honest-but-curious and the compelled operator is the point of the design.

## Adversaries out of scope

1. **Reporter-endpoint compromise.** If the reporter's device is compromised before encryption, no server-side design can help. Endpoint hardening is a separate layer.
2. **Traffic analysis.** Observing that a person contacted a reporting channel at all is a Tor-shaped problem, addressed at the network layer, not here.
3. **Recipient compromise after legitimate decryption.** Once an authorized case handler decrypts a report on their device, protecting that plaintext is an endpoint and process concern.
4. **Denial of service.** Availability attacks are out of scope for the confidentiality guarantees described here.

## Security properties

The protocol must provide:

1. **Operator zero-knowledge at rest.** The server stores ciphertext, wrapped keys, ephemeral public values, and opaque thread tokens. It cannot recover plaintext without the cooperation of a key-holding recipient.
2. **Reporter pseudonymity.** The operator cannot link a report to a reporter beyond what the reporter chose to reveal in the content.
3. **Forward secrecy across sessions.** Compromise of key material at one point in time does not retroactively decrypt earlier reports or earlier messages in a thread.
4. **Unlinkable acknowledgement.** A reporter can verify that their report was received and can retrieve replies, without the operator being able to link the acknowledgement back to the originating session.
5. **Public verifiability.** The protocol is specified in the open and is independently reviewable. Security does not rest on any vendor claim.

## Trust assumptions

- Recipient (case handler) private keys are held in hardware-backed storage (YubiKey-class devices or an HSM) and are never exposed to the server.
- The reporter obtains an authentic channel public key. Key distribution and its integrity are part of the protocol specification and are in scope for review.
- Cryptographic primitives (X25519, ChaCha20-Poly1305, and the chosen ratchet construction) are assumed sound; the contribution is their composition for this setting, not new primitives.

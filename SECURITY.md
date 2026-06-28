# Security policy

`e2ee-reports` is a cryptographic protocol and library for confidential reporting channels. Its threat model is documented in [docs/threat-model.md](docs/threat-model.md). Review and scrutiny are welcome.

## Reporting a vulnerability

Report suspected vulnerabilities privately to **yaro@ethicsportal.eu**. Please do not open a public issue for a security problem before it has been addressed.

A useful report includes:

- The component or document affected (protocol design, reference implementation, or deployment).
- A description of the issue and the conditions under which it occurs.
- The impact you believe it has, mapped to the security properties in the threat model where possible.
- Any proof of concept, if you have one.

You can expect an acknowledgement of your report. Once an issue is confirmed and a fix or mitigation is prepared, the resolution is published together with credit to the reporter, unless you prefer to remain anonymous.

## Scope

In scope: the protocol design, the reference implementation, and the documented deployment patterns, as they relate to the security properties in the threat model (operator zero-knowledge at rest, reporter pseudonymity, forward secrecy across sessions, unlinkable acknowledgement, public verifiability).

Out of scope, per the threat model: reporter-endpoint compromise, traffic analysis, recipient compromise after legitimate decryption, and denial of service.

## Cryptography note

The primitives used (X25519, ChaCha20-Poly1305, and the chosen ratchet construction) are conventional and well-studied. The work of this project is their composition for the reporting-channel setting. Findings about that composition, the protocol shape, and key handling are the most valuable.

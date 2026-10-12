//! Reference implementation of the `e2ee-reports` protocol.
//!
//! A reporter encrypts a report to a channel's public key. The server stores
//! the resulting envelope and can never decrypt it. Only the holder of the
//! channel secret (the case handler) can open it.
//!
//! This is a prototype. See the README for which properties from
//! `docs/threat-model.md` are implemented and which are still open.

mod envelope;
mod error;

#[doc(hidden)]
pub use envelope::seal_with_ephemeral;
pub use envelope::{open, seal, ChannelPublicKey, ChannelSecret, Envelope, VERSION};
pub use error::Error;

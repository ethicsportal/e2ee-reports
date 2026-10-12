//! Sealing a report to a channel and opening it again.
//!
//! The reporter generates a fresh X25519 keypair per report, derives keys from
//! the shared secret with the channel's public key, and encrypts the report
//! with ChaCha20-Poly1305. The server only ever sees the envelope.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::thread::{Role, Thread};
use crate::Error;

pub const VERSION: u8 = 1;

const SALT: &[u8] = b"e2ee-reports v1";
const TAG_LEN: usize = 16;

/// The long-term secret of a reporting channel, held by case handlers.
pub struct ChannelSecret(StaticSecret);

impl ChannelSecret {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> ChannelPublicKey {
        ChannelPublicKey(PublicKey::from(&self.0))
    }
}

/// The public key reporters encrypt to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelPublicKey(PublicKey);

impl ChannelPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// What the server stores: a version byte, the reporter's ephemeral public
/// key, and the ciphertext. Nothing in it identifies the reporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    ephemeral_public: [u8; 32],
    ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + self.ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&version, rest) = bytes.split_first().ok_or(Error::Malformed)?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if rest.len() < 32 + TAG_LEN {
            return Err(Error::Malformed);
        }
        let (ephemeral, ciphertext) = rest.split_at(32);
        Ok(Self {
            ephemeral_public: ephemeral.try_into().expect("split at 32"),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// A sealed report: the envelope to upload, and the reporter's side of the
/// thread for reading replies later.
pub struct Sealed {
    pub envelope: Envelope,
    pub thread: Thread,
}

/// An opened report and the channel's side of its thread.
pub struct Opened {
    pub report: Vec<u8>,
    pub thread: Thread,
}

/// Encrypts a report to a channel.
pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    channel: &ChannelPublicKey,
    report: &[u8],
) -> Result<Sealed, Error> {
    let mut ephemeral = [0u8; 32];
    rng.fill_bytes(&mut ephemeral);
    let sealed = seal_with_ephemeral(ephemeral, channel, report);
    ephemeral.zeroize();
    sealed
}

/// Same as [`seal`] with caller-supplied ephemeral secret bytes.
///
/// Exists so test vectors are reproducible. Reusing an ephemeral secret
/// across reports breaks confidentiality; use [`seal`].
#[doc(hidden)]
pub fn seal_with_ephemeral(
    ephemeral_secret: [u8; 32],
    channel: &ChannelPublicKey,
    report: &[u8],
) -> Result<Sealed, Error> {
    let ephemeral = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&channel.0);
    if !shared.was_contributory() {
        return Err(Error::NonContributory);
    }

    let keys = ReportKeys::derive(shared.as_bytes(), ephemeral_public.as_bytes(), channel);
    let aad = associated_data(ephemeral_public.as_bytes(), channel);
    let ciphertext = keys.encrypt(report, &aad)?;

    Ok(Sealed {
        envelope: Envelope {
            ephemeral_public: *ephemeral_public.as_bytes(),
            ciphertext,
        },
        thread: Thread::from_root(&keys.thread_root, keys.thread_id, Role::Reporter),
    })
}

/// Decrypts an envelope with the channel secret.
pub fn open(channel: &ChannelSecret, envelope: &Envelope) -> Result<Opened, Error> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_public);
    let shared = channel.0.diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err(Error::NonContributory);
    }

    let channel_public = channel.public_key();
    let keys = ReportKeys::derive(
        shared.as_bytes(),
        &envelope.ephemeral_public,
        &channel_public,
    );
    let aad = associated_data(&envelope.ephemeral_public, &channel_public);
    let report = keys.decrypt(&envelope.ciphertext, &aad)?;
    Ok(Opened {
        report,
        thread: Thread::from_root(&keys.thread_root, keys.thread_id, Role::Recipient),
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ReportKeys {
    report_key: [u8; 32],
    thread_root: [u8; 32],
    thread_id: [u8; 16],
}

impl ReportKeys {
    fn derive(shared: &[u8; 32], ephemeral_public: &[u8; 32], channel: &ChannelPublicKey) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), shared);
        let mut keys = Self {
            report_key: [0; 32],
            thread_root: [0; 32],
            thread_id: [0; 16],
        };
        for (label, out) in [
            (b"report key".as_slice(), keys.report_key.as_mut_slice()),
            (b"thread root", keys.thread_root.as_mut_slice()),
            (b"thread id", keys.thread_id.as_mut_slice()),
        ] {
            hkdf.expand_multi_info(&[label, ephemeral_public, channel.as_bytes()], out)
                .expect("valid HKDF-SHA256 output length");
        }
        keys
    }

    // The report key is derived from a fresh ephemeral secret and used for
    // exactly one encryption, so a fixed nonce is safe here.
    fn encrypt(&self, report: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        ChaCha20Poly1305::new(Key::from_slice(&self.report_key))
            .encrypt(&Nonce::default(), Payload { msg: report, aad })
            .map_err(|_| Error::Malformed)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        ChaCha20Poly1305::new(Key::from_slice(&self.report_key))
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Decryption)
    }
}

fn associated_data(ephemeral_public: &[u8; 32], channel: &ChannelPublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 32);
    aad.push(VERSION);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(channel.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn sealed_report() -> (ChannelSecret, Envelope) {
        let channel = ChannelSecret::generate(&mut OsRng);
        let sealed = seal(
            &mut OsRng,
            &channel.public_key(),
            b"the director moved the funds",
        )
        .unwrap();
        (channel, sealed.envelope)
    }

    #[test]
    fn round_trip() {
        let (channel, envelope) = sealed_report();
        assert_eq!(
            open(&channel, &envelope).unwrap().report,
            b"the director moved the funds"
        );
    }

    #[test]
    fn round_trip_through_bytes() {
        let (channel, envelope) = sealed_report();
        let stored = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        assert_eq!(
            open(&channel, &stored).unwrap().report,
            b"the director moved the funds"
        );
    }

    #[test]
    fn another_channel_cannot_open() {
        let (_, envelope) = sealed_report();
        let other = ChannelSecret::generate(&mut OsRng);
        assert_eq!(open(&other, &envelope).err(), Some(Error::Decryption));
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let (channel, envelope) = sealed_report();
        let mut bytes = envelope.to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(open(&channel, &tampered).err(), Some(Error::Decryption));
    }

    #[test]
    fn swapped_ephemeral_key_is_rejected() {
        let (channel, envelope) = sealed_report();
        let (_, other) = sealed_report();
        let mut bytes = envelope.to_bytes();
        bytes[1..33].copy_from_slice(&other.to_bytes()[1..33]);
        let tampered = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(open(&channel, &tampered).err(), Some(Error::Decryption));
    }

    #[test]
    fn each_report_gets_a_fresh_ephemeral_key() {
        let channel = ChannelSecret::generate(&mut OsRng).public_key();
        let a = seal(&mut OsRng, &channel, b"same").unwrap().envelope;
        let b = seal(&mut OsRng, &channel, b"same").unwrap().envelope;
        assert_ne!(a.ephemeral_public, b.ephemeral_public);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn low_order_channel_key_is_refused() {
        let zero = ChannelPublicKey::from_bytes([0; 32]);
        assert_eq!(
            seal(&mut OsRng, &zero, b"x").err(),
            Some(Error::NonContributory)
        );
    }

    #[test]
    fn unknown_version_is_refused() {
        let (_, envelope) = sealed_report();
        let mut bytes = envelope.to_bytes();
        bytes[0] = 2;
        assert_eq!(
            Envelope::from_bytes(&bytes),
            Err(Error::UnsupportedVersion(2))
        );
    }

    #[test]
    fn truncated_envelope_is_malformed() {
        assert_eq!(Envelope::from_bytes(&[VERSION; 40]), Err(Error::Malformed));
        assert_eq!(Envelope::from_bytes(&[]), Err(Error::Malformed));
    }
}

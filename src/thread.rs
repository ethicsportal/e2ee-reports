//! Follow-up messages on a report.
//!
//! Sealing a report also derives a thread root that only the reporter and the
//! channel can compute. From it come two symmetric KDF chains, one per
//! direction. Every message advances its chain and the previous chain key is
//! overwritten, so state captured later cannot decrypt earlier messages.
//!
//! This is forward secrecy only. A symmetric chain does not heal after a
//! compromise; a Diffie-Hellman ratchet that survives weeks of inactivity is
//! still an open design question (see `docs/protocol.md`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, VERSION};

const TAG_LEN: usize = 16;
const STATE_LEN: usize = 1 + 1 + 16 + (32 + 4) * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Reporter,
    Recipient,
}

impl Role {
    fn sends(self) -> Direction {
        match self {
            Role::Reporter => Direction::ToRecipient,
            Role::Recipient => Direction::ToReporter,
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    ToRecipient = 0,
    ToReporter = 1,
}

/// One side's view of a report thread.
pub struct Thread {
    id: [u8; 16],
    role: Role,
    send: Chain,
    receive: Chain,
}

/// A follow-up message as the server stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadMessage {
    counter: u32,
    ciphertext: Vec<u8>,
}

impl ThreadMessage {
    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + self.ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&version, rest) = bytes.split_first().ok_or(Error::Malformed)?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if rest.len() < 4 + TAG_LEN {
            return Err(Error::Malformed);
        }
        let (counter, ciphertext) = rest.split_at(4);
        Ok(Self {
            counter: u32::from_be_bytes(counter.try_into().expect("split at 4")),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

impl Thread {
    pub(crate) fn from_root(root: &[u8; 32], id: [u8; 16], role: Role) -> Self {
        let to_recipient = Chain::start(root, b"reporter to recipient");
        let to_reporter = Chain::start(root, b"recipient to reporter");
        let (send, receive) = match role {
            Role::Reporter => (to_recipient, to_reporter),
            Role::Recipient => (to_reporter, to_recipient),
        };
        Self {
            id,
            role,
            send,
            receive,
        }
    }

    /// Identifier the server files thread messages under. It is derived from
    /// the report's key exchange and says nothing about who the reporter is.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Result<ThreadMessage, Error> {
        let counter = self.send.counter;
        let (message_key, next) = self.send.step()?;
        let aad = associated_data(&self.id, self.role.sends(), counter);
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(message_key.as_slice()))
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: message,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Malformed)?;
        self.send = next;
        Ok(ThreadMessage {
            counter,
            ciphertext,
        })
    }

    /// Messages must be read in order. The chain only moves forward once a
    /// message authenticates, so a forged message cannot desynchronise it.
    pub fn decrypt(&mut self, message: &ThreadMessage) -> Result<Vec<u8>, Error> {
        if message.counter != self.receive.counter {
            return Err(Error::OutOfOrder {
                expected: self.receive.counter,
                got: message.counter,
            });
        }
        let (message_key, next) = self.receive.step()?;
        let direction = match self.role {
            Role::Reporter => Direction::ToReporter,
            Role::Recipient => Direction::ToRecipient,
        };
        let aad = associated_data(&self.id, direction, message.counter);
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(message_key.as_slice()))
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: &message.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Decryption)?;
        self.receive = next;
        Ok(plaintext)
    }

    /// Serialises the thread state so a reporter can resume weeks later.
    /// The bytes are secret: anyone holding them can read future replies.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(STATE_LEN));
        out.push(VERSION);
        out.push(self.role as u8);
        out.extend_from_slice(&self.id);
        for chain in [&self.send, &self.receive] {
            out.extend_from_slice(&chain.key);
            out.extend_from_slice(&chain.counter.to_be_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != STATE_LEN {
            return Err(Error::Malformed);
        }
        if bytes[0] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[0]));
        }
        let role = match bytes[1] {
            0 => Role::Reporter,
            1 => Role::Recipient,
            _ => return Err(Error::Malformed),
        };
        let id = bytes[2..18].try_into().expect("16 bytes");
        let chain_at = |offset: usize| Chain {
            key: bytes[offset..offset + 32].try_into().expect("32 bytes"),
            counter: u32::from_be_bytes(
                bytes[offset + 32..offset + 36].try_into().expect("4 bytes"),
            ),
        };
        Ok(Self {
            id,
            role,
            send: chain_at(18),
            receive: chain_at(54),
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Chain {
    key: [u8; 32],
    counter: u32,
}

impl Chain {
    fn start(root: &[u8; 32], label: &[u8]) -> Self {
        let mut key = [0u8; 32];
        expand(root, &[b"chain start", label], &mut key);
        Self { key, counter: 0 }
    }

    /// Returns this step's message key and the chain's next state without
    /// touching the current one.
    fn step(&self) -> Result<(Zeroizing<[u8; 32]>, Chain), Error> {
        let counter = self.counter.checked_add(1).ok_or(Error::Malformed)?;
        let mut message_key = Zeroizing::new([0u8; 32]);
        expand(&self.key, &[b"message key"], message_key.as_mut());
        let mut next = Chain {
            key: [0; 32],
            counter,
        };
        expand(&self.key, &[b"chain key"], &mut next.key);
        Ok((message_key, next))
    }
}

fn expand(prk: &[u8; 32], info: &[&[u8]], out: &mut [u8]) {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("32-byte PRK is valid for SHA-256")
        .expand_multi_info(info, out)
        .expect("valid HKDF-SHA256 output length");
}

fn associated_data(id: &[u8; 16], direction: Direction, counter: u32) -> [u8; 22] {
    let mut aad = [0u8; 22];
    aad[0] = VERSION;
    aad[1..17].copy_from_slice(id);
    aad[17] = direction as u8;
    aad[18..].copy_from_slice(&counter.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open, seal, ChannelSecret};
    use rand_core::OsRng;

    fn new_thread() -> (Thread, Thread) {
        let channel = ChannelSecret::generate(&mut OsRng);
        let sealed = seal(&mut OsRng, &channel.public_key(), b"report").unwrap();
        let opened = open(&channel, &sealed.envelope).unwrap();
        (sealed.thread, opened.thread)
    }

    #[test]
    fn both_sides_agree_on_the_thread_id() {
        let (reporter, recipient) = new_thread();
        assert_eq!(reporter.id(), recipient.id());
        assert_eq!(reporter.role(), Role::Reporter);
        assert_eq!(recipient.role(), Role::Recipient);
    }

    #[test]
    fn conversation_in_both_directions() {
        let (mut reporter, mut recipient) = new_thread();

        let question = recipient.encrypt(b"which account?").unwrap();
        assert_eq!(reporter.decrypt(&question).unwrap(), b"which account?");

        let answer = reporter.encrypt(b"the one in Cyprus").unwrap();
        assert_eq!(recipient.decrypt(&answer).unwrap(), b"the one in Cyprus");

        let follow_up = recipient.encrypt(b"thanks, we are on it").unwrap();
        assert_eq!(follow_up.counter(), 1);
        assert_eq!(
            reporter.decrypt(&follow_up).unwrap(),
            b"thanks, we are on it"
        );
    }

    #[test]
    fn resumes_from_saved_state() {
        let (reporter, mut recipient) = new_thread();
        let saved = reporter.to_bytes();
        drop(reporter);

        let reply = recipient.encrypt(b"weeks later").unwrap();
        let mut reporter = Thread::from_bytes(&saved).unwrap();
        assert_eq!(reporter.decrypt(&reply).unwrap(), b"weeks later");
    }

    #[test]
    fn later_state_cannot_read_earlier_messages() {
        let (mut reporter, mut recipient) = new_thread();
        let first = reporter.encrypt(b"first").unwrap();
        let second = reporter.encrypt(b"second").unwrap();
        recipient.decrypt(&first).unwrap();
        recipient.decrypt(&second).unwrap();

        // Rewind the receive counter so the order check can't be what stops
        // it: the seized state must lack the key itself.
        let mut seized = recipient.to_bytes().to_vec();
        seized[86..90].copy_from_slice(&0u32.to_be_bytes());
        let mut seized = Thread::from_bytes(&seized).unwrap();
        assert_eq!(seized.decrypt(&first), Err(Error::Decryption));
    }

    #[test]
    fn forged_message_does_not_advance_the_chain() {
        let (mut reporter, mut recipient) = new_thread();
        let real = recipient.encrypt(b"real").unwrap();
        let mut forged = real.clone();
        *forged.ciphertext.last_mut().unwrap() ^= 1;

        assert_eq!(reporter.decrypt(&forged), Err(Error::Decryption));
        assert_eq!(reporter.decrypt(&real).unwrap(), b"real");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut reporter, mut recipient) = new_thread();
        let message = recipient.encrypt(b"once").unwrap();
        reporter.decrypt(&message).unwrap();
        assert_eq!(
            reporter.decrypt(&message),
            Err(Error::OutOfOrder {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn messages_do_not_cross_threads() {
        let (mut reporter_a, _) = new_thread();
        let (_, mut recipient_b) = new_thread();
        let message = recipient_b.encrypt(b"for thread b").unwrap();
        assert_eq!(reporter_a.decrypt(&message), Err(Error::Decryption));
    }

    #[test]
    fn a_side_cannot_decrypt_its_own_messages() {
        let (mut reporter, _) = new_thread();
        let sent = reporter.encrypt(b"mine").unwrap();
        assert_eq!(reporter.decrypt(&sent), Err(Error::Decryption));
    }

    #[test]
    fn message_round_trips_through_bytes() {
        let (mut reporter, mut recipient) = new_thread();
        let message = recipient.encrypt(b"stored").unwrap();
        let stored = ThreadMessage::from_bytes(&message.to_bytes()).unwrap();
        assert_eq!(reporter.decrypt(&stored).unwrap(), b"stored");
    }

    #[test]
    fn corrupt_state_is_refused() {
        let (reporter, _) = new_thread();
        let mut saved = reporter.to_bytes().to_vec();
        saved[1] = 7;
        assert!(matches!(Thread::from_bytes(&saved), Err(Error::Malformed)));
        assert!(matches!(
            Thread::from_bytes(&saved[..10]),
            Err(Error::Malformed)
        ));
    }
}

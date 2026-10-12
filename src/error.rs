use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input is too short or otherwise not a valid encoding.
    Malformed,
    /// Envelope or message carries a protocol version this build does not speak.
    UnsupportedVersion(u8),
    /// The Diffie-Hellman result was all zeros (low-order public key).
    NonContributory,
    /// Authentication failed: wrong key, or the data was modified.
    Decryption,
    /// A thread message arrived with an unexpected counter.
    OutOfOrder { expected: u32, got: u32 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed => write!(f, "malformed input"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Error::NonContributory => write!(f, "non-contributory key exchange"),
            Error::Decryption => write!(f, "decryption failed"),
            Error::OutOfOrder { expected, got } => {
                write!(f, "out-of-order message: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Below the floors (a downgrade) or above the ceilings (work a server shouldn't impose).
    #[error("KDF parameters rejected: {0}")]
    KdfRejected(&'static str),
    #[error("key derivation failed")]
    Kdf,
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("signature verification failed")]
    Signature,
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("unsupported format version {0}")]
    Version(u8),
    #[error("envelope was encrypted with a different vault key")]
    KeyIdMismatch,
    #[error("plaintext too large ({0} bytes)")]
    TooLarge(usize),
    #[error("system random number generator failed")]
    Rng,
}

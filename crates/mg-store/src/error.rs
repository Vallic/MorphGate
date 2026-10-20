#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no vault has been set up yet")]
    NotInitialized,
    #[error("a vault already exists")]
    AlreadyInitialized,
    #[error("the vault is locked")]
    Locked,
    #[error("wrong master password")]
    WrongPassword,
    #[error("that recovery key does not match this vault")]
    WrongRecoveryKey,
    #[error("item {0} not found")]
    NotFound(String),
    #[error("item {id} is a {existing}, not a {requested}")]
    TypeMismatch {
        id: String,
        existing: &'static str,
        requested: &'static str,
    },
    #[error("{0}")]
    Invalid(String),
    #[error("this vault is read-only for you")]
    ReadOnly,
    #[error("no such vault on this device")]
    UnknownVault,
    #[error("item {item} was written by an account this device can't verify ({author})")]
    UnverifiedAuthor { item: String, author: String },
    #[error("{0}")]
    Untrusted(String),
    #[error("vault data is corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Crypto(#[from] mg_vault::Error),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("vault file: {0}")]
    Io(#[from] std::io::Error),
}

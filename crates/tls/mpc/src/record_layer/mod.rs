//! TLS record layer.

pub(crate) mod aead;
mod decrypt;
mod encrypt;

pub(crate) use decrypt::{DecryptRecord, DecryptRequest, Decrypter};
pub(crate) use encrypt::{EncryptInfo, EncryptRecord, EncryptRequest, Encrypter};

/// Sets the visibility for en-/decryption operations.
pub(crate) enum Visibility {
    Private,
    Public,
}

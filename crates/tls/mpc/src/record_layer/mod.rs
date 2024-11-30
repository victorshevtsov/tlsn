//! TLS record layer.

pub(crate) mod aead;
mod decrypt;
mod encrypt;

pub(crate) use decrypt::{DecryptRequest, Decrypter};
pub(crate) use encrypt::{EncryptRequest, Encrypter};

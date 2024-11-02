//! A library for computing different kinds of hash functions in a 2PC setting.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod error;
#[cfg(feature = "ghash")]
pub mod ghash;
pub use error::UniversalHashError;

/// A trait supporting different kinds of hash functions.
pub trait UniversalHash {
    /// Sets the key for the hash function
    ///
    /// # Arguments
    ///
    /// * `key` - Key to use for the hash function.
    fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError>;

    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// # Arguments
    ///
    /// * `input` - Input to hash.
    fn finalize(&mut self, input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError>;
}

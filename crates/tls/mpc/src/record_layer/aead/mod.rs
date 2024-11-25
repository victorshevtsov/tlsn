//! Handles authenticated encryption, decryption and tags.

use mpz_memory_core::{
    binary::{Binary, U8},
    FromRaw, Slice, StaticSize, ToRaw, Vector,
};

pub(crate) mod decrypt;
pub(crate) use decrypt::{AesGcmDecrypt, Decrypt};
pub(crate) mod encrypt;
pub(crate) use encrypt::{AesGcmEncrypt, Encrypt};

pub(crate) mod ghash;

const START_COUNTER: u32 = 2;

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

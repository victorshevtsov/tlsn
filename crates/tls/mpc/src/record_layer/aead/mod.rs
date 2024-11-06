//! Handles authenticated encryption, decryption and tags.

use mpz_memory_core::{
    binary::{Binary, U8},
    FromRaw, Slice, StaticSize, ToRaw, Vector,
};

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod ghash;

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

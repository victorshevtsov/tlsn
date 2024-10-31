use mpz_memory_core::{
    binary::{Binary, U8},
    FromRaw, Slice, StaticSize, ToRaw, Vector,
};

mod decrypt;
mod encrypt;
mod tag;

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

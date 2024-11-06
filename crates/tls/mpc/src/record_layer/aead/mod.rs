//! Handles authenticated encryption, decryption and tags.

use crate::{
    decode::{Decode, OneTimePadShared},
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use futures::{TryFuture, TryFutureExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeError, MemoryExt, StaticSize, Vector, View,
};
use mpz_memory_core::{DecodeFutureTyped, Memory};
use mpz_memory_core::{FromRaw, Slice, ToRaw};
use mpz_vm_core::Vm;

pub(crate) mod ghash;
use ghash::{Ghash, GhashCompute, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError, Tag};

const START_COUNTER: u32 = 2;

pub(crate) struct AesGcmEncrypt {
    role: TlsRole,
    keystream: Keystream<Aes128>,
    ghash: GhashCompute,
}

impl AesGcmEncrypt {
    /// Creates a new instance for encryption.
    ///
    /// # Arguments
    ///
    /// * `role` - The role of the party.
    /// * `keystream` - The keystream for AES-GCM.
    /// * `ghash` - An instance for computing Ghash.
    pub(crate) fn new(role: TlsRole, keystream: Keystream<Aes128>, ghash: GhashCompute) -> Self {
        Self {
            role,
            keystream,
            ghash,
        }
    }

    /// Preparation for encrypting a ciphertext.
    ///
    /// Returns [`Encrypt`] for async computation.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `plaintext_ref` - The VM plaintext reference.
    /// * `explicit_nonce` - The TLS explicit nonce.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Additional data for AEAD.
    #[allow(clippy::type_complexity)]
    pub(crate) fn encrypt<V>(
        &mut self,
        vm: &mut V,
        plaintext_ref: Vector<U8>,
        explicit_nonce: [u8; 8],
        plaintext: Vec<u8>,
        aad: [u8; 13],
    ) -> Result<
        (
            Encrypt<'_, DecodeFutureTyped<BitVec<u32>, Vec<u8>>>,
            Vector<U8>,
        ),
        MpcTlsError,
    >
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary>,
    {
        let j0 = self.keystream.j0(vm, explicit_nonce)?;
        let j0 = Decode::new(vm, self.role, transmute(j0))?;
        let j0 = j0.shared(vm)?;

        let keystream = self.keystream.chunk_sufficient(plaintext.len())?;

        let cipher_out = keystream
            .apply(vm, plaintext_ref)
            .map_err(MpcTlsError::vm)?;
        let cipher_ref = cipher_out
            .assign(vm, explicit_nonce, START_COUNTER, plaintext)
            .map_err(MpcTlsError::vm)?;

        let ciphertext = vm.decode(cipher_ref).map_err(MpcTlsError::vm)?;
        let encrypt = Encrypt {
            j0,
            ghash: &self.ghash,
            ciphertext,
            aad,
        };

        Ok((encrypt, cipher_ref))
    }
}

/// Encrypts a ciphertext.
pub(crate) struct Encrypt<'a, F> {
    j0: OneTimePadShared,
    ghash: &'a GhashCompute,
    ciphertext: F,
    aad: [u8; 13],
}

impl<'a, F> Encrypt<'a, F>
where
    F: TryFuture<Ok = Vec<u8>, Error = DecodeError>,
{
    /// Transforms the inner ciphertext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_cipher<T, U>(self, func: T) -> impl TryFuture<Ok = U, Error = DecodeError>
    where
        T: FnOnce(F::Ok) -> U,
    {
        self.ciphertext.map_ok(func)
    }

    /// Computes the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Vec<u8>, MpcTlsError>
    where
        Ctx: Context,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let ciphertext = self.ciphertext.map_err(MpcTlsError::decode);
        let (j0, mut ciphertext) = futures::try_join!(j0, ciphertext)?;

        let tag = Tag::compute(ctx, self.ghash, j0, &ciphertext, aad).await?;
        ciphertext.extend(tag.into_inner());

        Ok(ciphertext)
    }
}

//#[instrument(level = "trace", skip_all, err)]
//pub(crate) fn prepare_tag_for_encrypt<V, C>(
//    vm: &mut V,
//    role: TlsRole,
//    j0: <C as CipherCircuit>::Block,
//    ciphertext: Vector<U8>,
//    aad: Vec<u8>,
//) -> Result<TagCreator, MpcTlsError>
//where
//    V: Vm<Binary> + Memory<Binary> + View<Binary>,
//    C: CipherCircuit,
//{
//    let j0: Vector<U8> = transmute(j0);
//    let j0 = Decode::new(vm, role, j0)?;
//    let j0 = j0.shared(vm)?;
//
//    let ciphertext = vm.decode(ciphertext).map_err(MpcTlsError::vm)?;
//
//    let text = TagCreator {
//        j0,
//        ciphertext,
//        aad,
//    };
//
//    Ok(text)
//}
//
//pub(crate) struct TagCreator {
//    j0: OneTimePadShared,
//    ciphertext: DecodeFutureTyped<BitVec<u32>, Vec<u8>>,
//    aad: Vec<u8>,
//}
//
//impl TagCreator {
//    #[instrument(level = "trace", skip_all, err)]
//    pub(crate) async fn compute<Ctx, U, Sc>(
//        self,
//        ghash: &mut Ghash<Sc>,
//        ctx: &mut Ctx,
//    ) -> Result<Vec<u8>, MpcTlsError>
//    where
//        Ctx: Context,
//        Sc: ShareConvert<Gf2_128>,
//        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
//        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
//    {
//        let j0 = self.j0.decode().await?;
//        let aad = self.aad;
//
//        let mut ciphertext = self.ciphertext.await?;
//
//        let ciphertext_padded = build_ghash_data(aad, ciphertext.clone());
//        let hash = ghash.finalize(ciphertext_padded)?;
//
//        let tag_share = j0
//            .into_iter()
//            .zip(hash.into_iter())
//            .map(|(a, b)| a ^ b)
//            .collect();
//        let tag_share = Tag::new(tag_share);
//
//        let tag = add_tag_shares(ctx, tag_share).await?;
//        ciphertext.extend(&tag.into_inner());
//
//        Ok(ciphertext)
//    }
//}
//
//#[instrument(level = "trace", skip_all, err)]
//pub(crate) fn decrypt<V, C>(
//    vm: &mut V,
//    role: TlsRole,
//    keystream: &mut Keystream<C>,
//    explicit_nonce: <<C as CipherCircuit>::Nonce as Repr<Binary>>::Clear,
//    start_counter: u32,
//    mut ciphertext: Vec<u8>,
//    aad: Vec<u8>,
//) -> Result<PlainText, MpcTlsError>
//where
//    V: Vm<Binary> + View<Binary>,
//    C: CipherCircuit,
//    <<C as CipherCircuit>::Counter as Repr<Binary>>::Clear: From<[u8; 4]>,
//    <<C as CipherCircuit>::Nonce as Repr<Binary>>::Clear: Copy,
//{
//    let tag_bytes = ciphertext
//        .split_off(ciphertext.len() - <<C as CipherCircuit>::Block as StaticSize<Binary>>::SIZE);
//    let purported_tag = Tag::new(tag_bytes);
//
//    let len = ciphertext.len();
//    let block_size = <<C as CipherCircuit>::Block as StaticSize<Binary>>::SIZE / 8;
//    let block_count = (len / block_size) + (len % block_size != 0) as usize;
//
//    let j0 = keystream
//        .j0(vm, explicit_nonce)
//        .map_err(MpcTlsError::decrypt)?;
//    let j0: Vector<U8> = transmute(j0);
//    let j0 = Decode::new(vm, role, j0)?;
//    let j0 = j0.shared(vm)?;
//
//    let keystream = keystream.chunk(block_count).map_err(MpcTlsError::decrypt)?;
//    let cipher_ref = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
//    vm.mark_public(cipher_ref).map_err(MpcTlsError::vm)?;
//
//    let cipher_output = keystream
//        .apply(vm, cipher_ref)
//        .map_err(MpcTlsError::decrypt)?;
//
//    let plaintext = cipher_output
//        .assign(vm, explicit_nonce, start_counter, ciphertext.clone())
//        .map_err(MpcTlsError::decrypt)?;
//
//    let plaintext = PlainText {
//        role,
//        j0,
//        ciphertext,
//        purported_tag,
//        plaintext,
//        aad,
//    };
//
//    Ok(plaintext)
//}
//
//pub(crate) struct PlainText {
//    role: TlsRole,
//    j0: OneTimePadShared,
//    ciphertext: Vec<u8>,
//    purported_tag: Tag,
//    plaintext: Vector<U8>,
//    aad: Vec<u8>,
//}
//
//impl PlainText {
//    #[instrument(level = "trace", skip_all, err)]
//    pub(crate) async fn compute<Ctx, Sc>(
//        self,
//        ghash: &mut Ghash<Sc>,
//        ctx: &mut Ctx,
//    ) -> Result<Vector<U8>, MpcTlsError>
//    where
//        Ctx: Context,
//        Sc: ShareConvert<Gf2_128>,
//        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
//        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
//    {
//        let PlainText {
//            role,
//            j0,
//            ciphertext,
//            purported_tag,
//            plaintext,
//            aad,
//        } = self;
//
//        let j0 = j0.decode().await?;
//        let ciphertext = build_ghash_data(aad, ciphertext);
//        let hash = ghash.finalize(ciphertext)?;
//
//        let tag_share = j0
//            .into_iter()
//            .zip(hash.into_iter())
//            .map(|(a, b)| a ^ b)
//            .collect();
//        let tag_share = Tag::new(tag_share);
//
//        verify_tag(ctx, role, tag_share, purported_tag).await?;
//
//        Ok(plaintext)
//    }
//}

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

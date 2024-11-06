//! Handles authenticated encryption, decryption and tags.

use crate::{
    decode::{Decode, OneTimePadShared},
    MpcTlsError, TlsRole,
};
use cipher::{CipherCircuit, Keystream};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Repr, StaticSize, Vector, View, ViewExt,
};
use mpz_memory_core::{DecodeFutureTyped, Memory};
use mpz_memory_core::{FromRaw, Slice, ToRaw};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::Vm;
use tracing::instrument;

pub(crate) mod ghash;
use ghash::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError, Tag};

#[instrument(level = "trace", skip_all, err)]
pub(crate) fn prepare_tag_for_encrypt<V, C>(
    vm: &mut V,
    role: TlsRole,
    j0: <C as CipherCircuit>::Block,
    ciphertext: Vector<U8>,
    aad: Vec<u8>,
) -> Result<TagCreator, MpcTlsError>
where
    V: Vm<Binary> + Memory<Binary> + View<Binary>,
    C: CipherCircuit,
{
    let j0: Vector<U8> = transmute(j0);
    let j0 = Decode::new(vm, role, j0)?;
    let j0 = j0.shared(vm)?;

    let ciphertext = vm.decode(ciphertext).map_err(MpcTlsError::vm)?;

    let text = TagCreator {
        j0,
        ciphertext,
        aad,
    };

    Ok(text)
}

pub(crate) struct TagCreator {
    j0: OneTimePadShared,
    ciphertext: DecodeFutureTyped<BitVec<u32>, Vec<u8>>,
    aad: Vec<u8>,
}

impl TagCreator {
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn compute<Ctx, U, Sc>(
        self,
        ghash: &mut Ghash<Sc>,
        ctx: &mut Ctx,
    ) -> Result<Vec<u8>, MpcTlsError>
    where
        Ctx: Context,
        Sc: ShareConvert<Gf2_128>,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    {
        let j0 = self.j0.decode().await?;
        let aad = self.aad;

        let mut ciphertext = self.ciphertext.await?;

        let ciphertext_padded = build_ghash_data(aad, ciphertext.clone());
        let hash = ghash.finalize(ciphertext_padded)?;

        let tag_share = j0
            .into_iter()
            .zip(hash.into_iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let tag_share = Tag::new(tag_share);

        let tag = add_tag_shares(ctx, tag_share).await?;
        ciphertext.extend(&tag.into_inner());

        Ok(ciphertext)
    }
}

#[instrument(level = "trace", skip_all, err)]
pub(crate) fn decrypt<V, C>(
    vm: &mut V,
    role: TlsRole,
    keystream: &mut Keystream<C>,
    explicit_nonce: <<C as CipherCircuit>::Nonce as Repr<Binary>>::Clear,
    start_counter: u32,
    mut ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<PlainText, MpcTlsError>
where
    V: Vm<Binary> + View<Binary>,
    C: CipherCircuit,
    <<C as CipherCircuit>::Counter as Repr<Binary>>::Clear: From<[u8; 4]>,
    <<C as CipherCircuit>::Nonce as Repr<Binary>>::Clear: Copy,
{
    let tag_bytes = ciphertext
        .split_off(ciphertext.len() - <<C as CipherCircuit>::Block as StaticSize<Binary>>::SIZE);
    let purported_tag = Tag::new(tag_bytes);

    let len = ciphertext.len();
    let block_size = <<C as CipherCircuit>::Block as StaticSize<Binary>>::SIZE / 8;
    let block_count = (len / block_size) + (len % block_size != 0) as usize;

    let j0 = keystream
        .j0(vm, explicit_nonce)
        .map_err(MpcTlsError::decrypt)?;
    let j0: Vector<U8> = transmute(j0);
    let j0 = Decode::new(vm, role, j0)?;
    let j0 = j0.shared(vm)?;

    let keystream = keystream.chunk(block_count).map_err(MpcTlsError::decrypt)?;
    let cipher_ref = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
    vm.mark_public(cipher_ref).map_err(MpcTlsError::vm)?;

    let cipher_output = keystream
        .apply(vm, cipher_ref)
        .map_err(MpcTlsError::decrypt)?;

    let plaintext = cipher_output
        .assign(vm, explicit_nonce, start_counter, ciphertext.clone())
        .map_err(MpcTlsError::decrypt)?;

    let plaintext = PlainText {
        role,
        j0,
        ciphertext,
        purported_tag,
        plaintext,
        aad,
    };

    Ok(plaintext)
}

pub(crate) struct PlainText {
    role: TlsRole,
    j0: OneTimePadShared,
    ciphertext: Vec<u8>,
    purported_tag: Tag,
    plaintext: Vector<U8>,
    aad: Vec<u8>,
}

impl PlainText {
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn compute<Ctx, Sc>(
        self,
        ghash: &mut Ghash<Sc>,
        ctx: &mut Ctx,
    ) -> Result<Vector<U8>, MpcTlsError>
    where
        Ctx: Context,
        Sc: ShareConvert<Gf2_128>,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    {
        let PlainText {
            role,
            j0,
            ciphertext,
            purported_tag,
            plaintext,
            aad,
        } = self;

        let j0 = j0.decode().await?;
        let ciphertext = build_ghash_data(aad, ciphertext);
        let hash = ghash.finalize(ciphertext)?;

        let tag_share = j0
            .into_iter()
            .zip(hash.into_iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let tag_share = Tag::new(tag_share);

        verify_tag(ctx, role, tag_share, purported_tag).await?;

        Ok(plaintext)
    }
}

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

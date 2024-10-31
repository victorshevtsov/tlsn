//! Decryption of ciphertext.

use crate::{
    decode::{Decode, OneTimePadShared},
    record_layer::aead::tag::{build_ghash_data, verify_tag, Tag},
    record_layer::aead::transmute,
    MpcTlsError, TlsRole,
};
use cipher::{CipherCircuit, Keystream};
use mpz_circuits::types::ToBinaryRepr;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Repr, StaticSize, Vector, View, ViewExt,
};
use mpz_vm_core::Vm;
use tlsn_universal_hash::UniversalHash;

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
    pub(crate) async fn compute<Ctx, U>(
        self,
        universal_hash: &mut U,
        ctx: &mut Ctx,
    ) -> Result<Vector<U8>, MpcTlsError>
    where
        Ctx: Context,
        U: UniversalHash<Ctx>,
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
        let hash = universal_hash.finalize(ciphertext, ctx).await?;

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

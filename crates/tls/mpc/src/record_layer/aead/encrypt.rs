use crate::{
    decode::{Decode, OneTimePadShared},
    record_layer::aead::{
        tag::{add_tag_shares, build_ghash_data, Tag},
        transmute,
    },
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, CipherCircuit, Keystream};
use mpz_circuits::types::ToBinaryRepr;
use mpz_common::Context;
use mpz_core::{
    bitvec::BitVec,
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, ClearValue, DecodeFutureTyped, FromRaw, Memory, MemoryExt, Repr, Slice, StaticSize,
    ToRaw, Vector, View, ViewExt,
};
use mpz_vm_core::{Vm, VmExt};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use std::{
    future::Future,
    marker::PhantomData,
    ops::{Add, BitXor},
};
use tlsn_universal_hash::UniversalHash;
use tracing::instrument;

pub(crate) fn encrypt<V, C>(
    vm: &mut V,
    role: TlsRole,
    j0: <C as CipherCircuit>::Block,
    ciphertext: Vector<U8>,
    aad: Vec<u8>,
) -> Result<Tlstext, MpcTlsError>
where
    V: Vm<Binary> + Memory<Binary> + View<Binary>,
    C: CipherCircuit,
{
    let j0: Vector<U8> = transmute(j0);
    let j0 = Decode::new(vm, role, j0)?;
    let j0 = j0.shared(vm)?;

    let ciphertext = vm.decode(ciphertext).map_err(MpcTlsError::vm)?;

    let text = Tlstext {
        j0,
        ciphertext,
        aad,
    };

    Ok(text)
}

pub(crate) struct Tlstext {
    j0: OneTimePadShared,
    ciphertext: DecodeFutureTyped<BitVec<u32>, Vec<u8>>,
    aad: Vec<u8>,
}

impl Tlstext {
    pub(crate) async fn compute<Ctx, U>(
        self,
        universal_hash: &mut U,
        ctx: &mut Ctx,
    ) -> Result<Vec<u8>, MpcTlsError>
    where
        Ctx: Context,
        U: UniversalHash<Ctx>,
    {
        let j0 = self.j0.decode().await?;
        let aad = self.aad;

        let ciphertext = self.ciphertext.await?;

        let mut ciphertext = build_ghash_data(aad, ciphertext);
        let hash = universal_hash.finalize(ciphertext.clone(), ctx).await?;

        let tag_share = j0
            .into_iter()
            .zip(hash.into_iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let tag_share = Tag::new(tag_share);

        let tag = add_tag_shares(ctx, tag_share).await?;

        ciphertext.extend_from_slice(&tag.into_inner());
        Ok(ciphertext)
    }
}

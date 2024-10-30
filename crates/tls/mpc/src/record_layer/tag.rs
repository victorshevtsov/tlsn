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

use crate::{
    decode::{Decode, OneTimePadShared},
    MpcTlsError, TlsRole,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Tag(Vec<u8>);

impl Tag {
    /// Creates a new tag.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for Tag {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let tag = self
            .0
            .into_iter()
            .zip(rhs.0.into_iter())
            .map(|(a, b)| a ^ b)
            .collect();

        Self(tag)
    }
}

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

pub(crate) fn decrypt<V, C>(
    vm: &mut V,
    role: TlsRole,
    keystream: &mut Keystream<C>,
    explicit_nonce: <<C as CipherCircuit>::Nonce as Repr<Binary>>::Clear,
    start_counter: u32,
    mut ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Plaintext, MpcTlsError>
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

    let plaintext = Plaintext {
        role,
        j0,
        ciphertext,
        purported_tag,
        plaintext,
        aad,
    };

    Ok(plaintext)
}

pub(crate) struct Plaintext {
    role: TlsRole,
    j0: OneTimePadShared,
    ciphertext: Vec<u8>,
    purported_tag: Tag,
    plaintext: Vector<U8>,
    aad: Vec<u8>,
}

impl Plaintext {
    pub(crate) async fn compute<Ctx, U>(
        self,
        universal_hash: &mut U,
        ctx: &mut Ctx,
    ) -> Result<Vector<U8>, MpcTlsError>
    where
        Ctx: Context,
        U: UniversalHash<Ctx>,
    {
        let Plaintext {
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

/// Computes the tag for a ciphertext and additional data.
///
/// The commit-reveal step is not required for computing a tag sent to the
/// Server, as it will be able to detect if the tag is incorrect.
#[instrument(level = "debug", skip_all, err)]
pub(crate) async fn add_tag_shares<Ctx: Context>(
    ctx: &mut Ctx,
    share: Tag,
) -> Result<Tag, MpcTlsError> {
    // TODO: The follower doesn't really need to learn the tag,
    // we could reduce some latency by not sending it.
    let io = ctx.io_mut();

    io.send(share.clone()).await?;
    let other_tag_share: Tag = io.expect_next().await?;

    let tag = share + other_tag_share;

    Ok(tag)
}

/// Verifies a purported tag against the ciphertext and additional data.
///
/// Verifying a tag requires a commit-reveal protocol between the leader and
/// follower. Without it, the party which receives the other's tag share first
/// could trivially compute a tag share which would cause an invalid message to
/// be accepted.
#[instrument(level = "debug", skip_all, err)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_tag<Ctx: Context>(
    ctx: &mut Ctx,
    role: TlsRole,
    share: Tag,
    purported_tag: Tag,
) -> Result<(), MpcTlsError> {
    let io = ctx.io_mut();
    let tag = match role {
        TlsRole::Leader => {
            // Send commitment of tag share to follower.
            let (decommitment, commitment) = share.clone().hash_commit();

            io.send(commitment).await?;

            let follower_share: Tag = io.expect_next().await?;

            // Send decommitment (tag share) to follower.
            io.send(decommitment).await?;

            share + follower_share
        }
        TlsRole::Follower => {
            // Wait for commitment from leader.
            let commitment: Hash = io.expect_next().await?;

            // Send tag share to leader.
            io.send(share.clone()).await?;

            // Expect decommitment (tag share) from leader.
            let decommitment: Decommitment<Tag> = io.expect_next().await?;

            // Verify decommitment.
            decommitment.verify(&commitment).map_err(|_| {
                MpcTlsError::peer("leader tag share commitment verification failed")
            })?;

            let leader_share = decommitment.into_inner();

            share + leader_share
        }
    };

    // Reject if tag is incorrect.
    if tag.into_inner() != purported_tag.into_inner() {
        return Err(MpcTlsError::tag("invalid tag"));
    }

    Ok(())
}

/// Builds padded data for GHASH.
fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // Pad data to be a multiple of 16 bytes.
    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
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

use crate::{
    decode::{Decode, OneTimePadShared},
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
pub(crate) fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
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

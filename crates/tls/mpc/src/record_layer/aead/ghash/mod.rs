//! This module implements Ghash.

use crate::{MpcTlsError, TlsRole};
use mpz_common::Context;
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use std::ops::Add;
use tracing::instrument;

mod error;
mod ghash_core;
mod ghash_inner;
pub(crate) use error::UniversalHashError;
pub(crate) use ghash_inner::{
    Ghash, GhashCompute, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError,
};

/// Contains data needed to compute tags.
pub(crate) struct TagComputer {
    j0s: Vec<Vec<u8>>,
    ciphertexts: Vec<Vec<u8>>,
    aads: Vec<[u8; 13]>,
}

impl TagComputer {
    /// Creates a new instance.
    pub(crate) fn new(j0s: Vec<Vec<u8>>, ciphertexts: Vec<Vec<u8>>, aads: Vec<[u8; 13]>) -> Self {
        Self {
            j0s,
            ciphertexts,
            aads,
        }
    }

    /// Computes the tag for a ciphertext and additional data.
    ///
    /// The commit-reveal step is not required for computing a tag sent to the
    /// server, as it will be able to detect if the tag is incorrect.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    /// * `ghash` - An instance for computing ghash.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn compute<Ctx>(
        self,
        ctx: &mut Ctx,
        ghash: &GhashCompute,
    ) -> Result<TagBatch, MpcTlsError>
    where
        Ctx: Context,
    {
        let mut shares = Vec::with_capacity(self.ciphertexts.len());
        for ((j0, ciphertext), aad) in self.j0s.into_iter().zip(self.ciphertexts).zip(self.aads) {
            let ciphertext_padded = build_ghash_data(aad.to_vec(), ciphertext);
            let hash = ghash.compute(ciphertext_padded)?;
            let tag_share: Vec<u8> = j0
                .into_iter()
                .zip(hash.into_iter())
                .map(|(a, b)| a ^ b)
                .collect();
            shares.push(Tag(tag_share));
        }

        let batch = TagBatch(shares);
        let batch = batch.combine(ctx).await?;

        Ok(batch)
    }
}

/// A batch of several tags
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TagBatch(Vec<Tag>);

impl TagBatch {
    pub(crate) async fn combine<Ctx>(self, ctx: &mut Ctx) -> Result<Self, MpcTlsError>
    where
        Ctx: Context,
    {
        // TODO: The follower doesn't really need to learn the tag,
        // we could reduce some latency by not sending it.
        let io = ctx.io_mut();

        io.send(self.clone()).await?;
        let other_batch: TagBatch = io.expect_next().await?;
        let tags = self
            .0
            .into_iter()
            .zip(other_batch.0)
            .map(|(first, second)| first + second)
            .collect();
        Ok(TagBatch(tags))
    }

    /// Verifies purported tag batch against `self`.
    ///
    /// Verifying a tag requires a commit-reveal protocol between the leader and
    /// follower. Without it, the party which receives the other's tag share first
    /// could trivially compute a tag share which would cause an invalid message to
    /// be accepted.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    /// * `role` - The role of the party.
    /// * `purported_batch` - The tags to verify against `self`.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn verify<Ctx>(
        self,
        ctx: &mut Ctx,
        role: TlsRole,
        purported_batch: TagBatch,
    ) -> Result<(), MpcTlsError>
    where
        Ctx: Context,
    {
        let io = ctx.io_mut();
        let batch = match role {
            TlsRole::Leader => {
                // Send commitment to follower.
                let (decommitment, commitment) = self.clone().hash_commit();

                io.send(commitment).await?;

                let follower_batch: TagBatch = io.expect_next().await?;

                // Send decommitment to follower.
                io.send(decommitment).await?;

                self + follower_batch
            }
            TlsRole::Follower => {
                // Wait for commitment from leader.
                let commitment: Hash = io.expect_next().await?;

                // Send tag batch to leader.
                io.send(self.clone()).await?;

                // Expect decommitment from leader.
                let decommitment: Decommitment<TagBatch> = io.expect_next().await?;

                // Verify decommitment.
                decommitment.verify(&commitment).map_err(|_| {
                    MpcTlsError::peer("leader tag share commitment verification failed")
                })?;

                let leader_batch = decommitment.into_inner();

                self + leader_batch
            }
        };

        // Reject if tag is incorrect.
        if batch != purported_batch {
            return Err(MpcTlsError::tag("invalid tag"));
        }

        Ok(())
    }

    /// Returns the inner tags.
    pub(crate) fn into_inner(self) -> Vec<Tag> {
        self.0
    }
}

impl Add for TagBatch {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let batch = self
            .into_inner()
            .into_iter()
            .zip(rhs.into_inner())
            .map(|(a, b)| a + b)
            .collect();
        Self(batch)
    }
}

/// An authentication tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Tag(Vec<u8>);

impl Tag {
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
        let tag = self.0.into_iter().zip(rhs.0).map(|(a, b)| a ^ b).collect();
        Self(tag)
    }
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

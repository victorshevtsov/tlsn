//! This module implements [`UniversalHash`](super::UniversalHash) for Ghash.

use crate::{decode::OneTimePadShared, MpcTlsError, TlsRole};
use mpz_common::Context;
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use mpz_fields::gf2_128::Gf2_128;
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use std::{future::Future, ops::Add};
use tracing::instrument;

mod error;
mod ghash_core;
mod ghash_inner;
pub(crate) use error::UniversalHashError;
pub(crate) use ghash_inner::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Tag(Vec<u8>);

impl Tag {
    /// Computes the tag for a ciphertext and additional data.
    ///
    /// The commit-reveal step is not required for computing a tag sent to the
    /// server, as it will be able to detect if the tag is incorrect.
    ///
    /// # Arguments
    ///
    /// * `ctx`         - The context for IO.
    /// * `ghash`       - An instance for computing ghash.
    /// * `j0`          - A share of the j0 block.
    /// * `ciphertext`  - A future resolving to ciphertext.
    /// * `aad`         - Additional data for AEAD.
    pub(crate) async fn compute<Ctx, C, J, Sc>(
        ctx: &mut Ctx,
        ghash: &mut Ghash<Sc>,
        j0: OneTimePadShared,
        ciphertext: C,
        aad: Vec<u8>,
    ) -> Result<Self, MpcTlsError>
    where
        Ctx: Context,
        C: Future<Output = Result<Vec<u8>, MpcTlsError>>,
        Sc: ShareConvert<Gf2_128>,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    {
        let j0 = j0.decode().await?;
        let ciphertext = ciphertext.await?;

        let ciphertext_padded = build_ghash_data(aad, ciphertext.clone());
        let hash = ghash.finalize(ciphertext_padded)?;

        let tag_share = j0
            .into_iter()
            .zip(hash.into_iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let tag_share = Tag(tag_share);

        // TODO: The follower doesn't really need to learn the tag,
        // we could reduce some latency by not sending it.
        let io = ctx.io_mut();

        io.send(tag_share.clone()).await?;
        let other_tag_share: Tag = io.expect_next().await?;

        let tag = tag_share + other_tag_share;
        Ok(tag)
    }

    /// Verifies a purported tag against `self`.
    ///
    /// Verifying a tag requires a commit-reveal protocol between the leader and
    /// follower. Without it, the party which receives the other's tag share first
    /// could trivially compute a tag share which would cause an invalid message to
    /// be accepted.
    ///
    /// # Arguments
    ///
    /// * `ctx`           - The context for IO.
    /// * `role`          - The role of the party.
    /// * `purported_tag` - The tag to verify against `self`.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn verify<Ctx: Context>(
        self,
        ctx: &mut Ctx,
        role: TlsRole,
        purported_tag: Vec<u8>,
    ) -> Result<(), MpcTlsError> {
        let io = ctx.io_mut();
        let tag = match role {
            TlsRole::Leader => {
                // Send commitment of tag share to follower.
                let (decommitment, commitment) = self.clone().hash_commit();

                io.send(commitment).await?;

                let follower_share: Tag = io.expect_next().await?;

                // Send decommitment (tag share) to follower.
                io.send(decommitment).await?;

                self + follower_share
            }
            TlsRole::Follower => {
                // Wait for commitment from leader.
                let commitment: Hash = io.expect_next().await?;

                // Send tag share to leader.
                io.send(self.clone()).await?;

                // Expect decommitment (tag share) from leader.
                let decommitment: Decommitment<Tag> = io.expect_next().await?;

                // Verify decommitment.
                decommitment.verify(&commitment).map_err(|_| {
                    MpcTlsError::peer("leader tag share commitment verification failed")
                })?;

                let leader_share = decommitment.into_inner();

                self + leader_share
            }
        };

        let purported_tag = Tag(purported_tag);

        // Reject if tag is incorrect.
        if tag != purported_tag {
            return Err(MpcTlsError::tag("invalid tag"));
        }

        Ok(())
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

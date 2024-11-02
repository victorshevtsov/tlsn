use crate::{
    ghash::ghash_core::{
        state::{Finalized, Intermediate},
        GhashCore,
    },
    UniversalHash, UniversalHashError,
};
use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_share_conversion::{ReceiverError, SenderError, ShareConvert};
use std::fmt::Debug;
use tracing::instrument;

mod config;
#[cfg(feature = "ideal")]
pub(crate) mod ideal;

pub use config::{GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

#[derive(Debug)]
enum State {
    Init,
    Ready { core: GhashCore<Finalized> },
    Error,
}

/// This is the common instance used by both sender and receiver.
///
/// It is an aio wrapper which mostly uses [`GhashCore`] for computation.
pub struct Ghash<C> {
    state: State,
    config: GhashConfig,
    converter: C,
}

impl<C> Ghash<C> {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `config`      - The configuration for this Ghash instance.
    /// * `converter`   - An instance which allows to convert multiplicative into additive shares
    ///                   and vice versa.
    /// * `context`     - The context.
    pub fn new(config: GhashConfig, converter: C) -> Self {
        Self {
            state: State::Init,
            config,
            converter,
        }
    }

    /// Computes all the additive shares of the hashkey powers.
    ///
    /// We need this when the max block count changes.
    #[instrument(level = "debug", skip_all, err)]
    async fn compute_add_shares<Ctx>(
        &mut self,
        core: GhashCore<Intermediate>,
        ctx: &mut Ctx,
    ) -> Result<GhashCore<Finalized>, UniversalHashError>
    where
        Ctx: Context,
        C: ShareConvert<Gf2_128>,
    {
        let odd_mul_shares = core.odd_mul_shares();

        let add_shares = self.converter.to_additive(ctx, odd_mul_shares).await?;
        let core = core.add_new_add_shares(&add_shares);

        Ok(core)
    }
}

impl<C> Debug for Ghash<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ghash")
            .field("state", &self.state)
            .field("config", &self.config)
            .field("converter", &"{{ .. }}".to_string())
            .finish()
    }
}

impl<C> UniversalHash for Ghash<C>
where
    C: ShareConvert<Gf2_128> + Send,
{
    fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError> {
        if key.len() != 16 {
            return Err(UniversalHashError::key(format!(
                "key length should be 16 bytes but is {}",
                key.len()
            )));
        }

        let State::Init = self.state else {
            return Err(UniversalHashError::state("Key already set".to_string()));
        };

        let mut h_additive = [0u8; 16];
        h_additive.copy_from_slice(key.as_slice());

        // GHASH reflects the bits of the key.
        let h_additive = Gf2_128::new(u128::from_be_bytes(h_additive).reverse_bits());

        let h_multiplicative = self
            .converter
            .to_multiplicative(ctx, vec![h_additive])
            .await?;

        let core = GhashCore::new(self.config.block_count);
        let core = core.compute_odd_mul_powers(h_multiplicative[0]);
        let core = self.compute_add_shares(core, ctx).await?;

        self.state = State::Ready { core };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    fn finalize(&mut self, mut input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError> {
        // Divide by block length and round up.
        let block_count = input.len() / 16 + (input.len() % 16 != 0) as usize;

        if block_count > self.config.block_count {
            return Err(UniversalHashError::input(format!(
                "block length of input should be {} max, but is {}",
                self.config.block_count, block_count
            )));
        }

        let state = std::mem::replace(&mut self.state, State::Error);

        // Calling finalize when not setup is a fatal error.
        let State::Ready { core } = state else {
            return Err(UniversalHashError::state("key not set"));
        };

        // Pad input to a multiple of 16 bytes.
        input.resize(block_count * 16, 0);

        // Convert input to blocks.
        let blocks = input
            .chunks_exact(16)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                Block::from(block)
            })
            .collect::<Vec<Block>>();

        let tag = core
            .finalize(&blocks)
            .expect("Input length should be valid");

        // Reinsert state.
        self.state = State::Ready { core };

        Ok(tag.to_bytes().to_vec())
    }
}

#[async_trait]
impl<C, Ctx> Flush<Ctx> for Ghash<C>
where
    C: ShareConvert<Gf2_128> + Send,
    Ctx: Context,
{
    type Error = UniversalHashError;

    fn wants_flush(&self) -> bool {
        todo!()
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ghash::{Ghash, GhashConfig},
        UniversalHash,
    };
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use mpz_common::executor::test_st_executor;
    use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn create_pair(block_count: usize) -> (Ghash<IdealShareConverter>, Ghash<IdealShareConverter>) {
        let (convert_a, convert_b) = ideal_share_converter();

        let config = GhashConfig::builder()
            .block_count(block_count)
            .build()
            .unwrap();

        (
            Ghash::new(config.clone(), convert_a),
            Ghash::new(config, convert_b),
        )
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec(), &mut ctx_a),
            receiver.set_key(receiver_key.to_be_bytes().to_vec(), &mut ctx_b)
        )
        .unwrap();

        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(message.clone(), &mut ctx_a),
            receiver.finalize(message.clone(), &mut ctx_b)
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_output_padded() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;

        // Message length is not a multiple of the block length
        let message: Vec<u8> = (0..126).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec(), &mut ctx_a),
            receiver.set_key(receiver_key.to_be_bytes().to_vec(), &mut ctx_b)
        )
        .unwrap();

        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(message.clone(), &mut ctx_a),
            receiver.finalize(message.clone(), &mut ctx_b)
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_long_message() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let short_message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        // A longer message.
        let long_message: Vec<u8> = (0..192).map(|_| rng.gen()).collect();

        // Create and setup sender and receiver for short message length.
        let (mut sender, mut receiver) = create_pair(1);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec(), &mut ctx_a),
            receiver.set_key(receiver_key.to_be_bytes().to_vec(), &mut ctx_b)
        )
        .unwrap();

        // Compute the shares for the short message.
        tokio::try_join!(
            sender.finalize(short_message.clone(), &mut ctx_a),
            receiver.finalize(short_message.clone(), &mut ctx_b)
        )
        .unwrap();

        // Now compute the shares for the longer message.
        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(long_message.clone(), &mut ctx_a),
            receiver.finalize(long_message.clone(), &mut ctx_b)
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));

        // We should still be able to generate a Ghash output for the shorter message.
        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(short_message.clone(), &mut ctx_a),
            receiver.finalize(short_message.clone(), &mut ctx_b)
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &short_message));
    }

    fn ghash_reference_impl(h: u128, message: &[u8]) -> Vec<u8> {
        let mut ghash = GhashReference::new(&h.to_be_bytes().into());
        ghash.update_padded(message);
        let mac = ghash.finalize();
        mac.to_vec()
    }
}

use crate::record_layer::aead::{
    ghash::error::UniversalHashError,
    ghash::ghash_core::{
        state::{Finalized, Intermediate},
        GhashCore,
    },
};
use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use std::{fmt::Debug, sync::Arc};

mod config;
pub(crate) use config::{GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

#[derive(Debug)]
enum State {
    Init,
    SetKey { key: Gf2_128 },
    MultKey { key: Gf2_128 },
    Ready { core: GhashCore<Finalized> },
    Done,
    Error,
}

/// This is the common instance used by both sender and receiver.
///
/// It is an aio wrapper which mostly uses [`GhashCore`] for computation.
pub(crate) struct Ghash<C> {
    state: State,
    config: GhashConfig,
    converter: C,
}

impl<C: ShareConvert<Gf2_128>> Ghash<C>
where
    C: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    C: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `config`      - The configuration for this Ghash instance.
    /// * `converter`   - An instance which allows to convert multiplicative into additive shares
    ///                   and vice versa.
    pub(crate) fn new(config: GhashConfig, converter: C) -> Self {
        Self {
            state: State::Init,
            config,
            converter,
        }
    }

    /// Allocates resources needed for ghash.
    pub(crate) fn alloc(&mut self) -> Result<(), UniversalHashError> {
        // We need only half the number of `block_count` M2As because of the free
        // squaring trick and we need one extra A2M conversion in the beginning.
        // Both M2A and A2M, each require a single OLE.
        AdditiveToMultiplicative::<Gf2_128>::alloc(&mut self.converter, 1)
            .map_err(UniversalHashError::conversion)?;

        MultiplicativeToAdditive::<Gf2_128>::alloc(
            &mut self.converter,
            self.config.block_count / 2,
        )
        .map_err(UniversalHashError::conversion)?;

        Ok(())
    }

    /// Sets the key for the hash function
    ///
    /// # Arguments
    ///
    /// * `key` - Key to use for the hash function.
    pub(crate) fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError> {
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

        self.state = State::SetKey { key: h_additive };

        Ok(())
    }

    /// Returns [`GhashCompute`] which can be used to compute ghash.
    ///
    /// When [`Ghash`] has been set up and is in [State::Ready], this functions returns a compute
    /// instance to compute ghash.
    pub(crate) fn finalize(&mut self) -> Result<GhashCompute, UniversalHashError> {
        let State::Ready { core } = std::mem::replace(&mut self.state, State::Error) else {
            return Err(UniversalHashError::state(
                "Finalize can only be called when in Ready state",
            ));
        };

        self.state = State::Done;
        let ghash = GhashCompute {
            core: Arc::new(core),
        };

        Ok(ghash)
    }

    /// Converts the additive key share into a multiplicative share.
    fn compute_multiplicative_share(
        &mut self,
    ) -> Result<<C as AdditiveToMultiplicative<Gf2_128>>::Future, UniversalHashError> {
        let State::SetKey { key } = self.state else {
            return Err(UniversalHashError::state(
                "UniversalHash should be in SetKey state",
            ));
        };

        let mult_key = self
            .converter
            .queue_to_multiplicative(&[key])
            .map_err(UniversalHashError::flush)?;

        Ok(mult_key)
    }

    /// Computes all the odd powers of the multiplicative key share and then converts them
    /// into additive shares.
    fn compute_additive_shares(
        &mut self,
    ) -> Result<
        (
            <C as MultiplicativeToAdditive<Gf2_128>>::Future,
            GhashCore<Intermediate>,
        ),
        UniversalHashError,
    > {
        let State::MultKey { key } = self.state else {
            return Err(UniversalHashError::state(
                "UniversalHash should be in MultKey state",
            ));
        };

        let core = GhashCore::new(self.config.block_count).compute_odd_mul_powers(key);
        let key_powers = core.odd_mul_shares();

        let add_keys = self
            .converter
            .queue_to_additive(&key_powers)
            .map_err(UniversalHashError::flush)?;

        Ok((add_keys, core))
    }
}

/// Computes ghash.
///
/// Once [`Ghash`] has been finalized with [`Ghash::finalize`] it returns [`GhashCompute`]
/// which can be used to compute ghash for data.
pub(crate) struct GhashCompute {
    core: Arc<GhashCore<Finalized>>,
}

impl Clone for GhashCompute {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl GhashCompute {
    /// Computes hash of the input, padding the input to the block size
    /// if needed.
    ///
    /// # Arguments
    ///
    /// * `input` - Input to hash.
    pub(crate) fn compute(&self, mut input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError> {
        // Divide by block length and round up.
        let block_count = input.len() / 16 + (input.len() % 16 != 0) as usize;

        if block_count > self.core.max_block_count() {
            return Err(UniversalHashError::input(format!(
                "block length of input should be {} max, but is {}",
                self.core.max_block_count(),
                block_count
            )));
        }

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

        let tag = self
            .core
            .finalize(&blocks)
            .expect("Input length should be valid");

        Ok(tag.to_bytes().to_vec())
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

#[async_trait]
impl<C, Ctx> Flush<Ctx> for Ghash<C>
where
    C: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    C: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    C: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    Ctx: Context,
{
    type Error = UniversalHashError;

    fn wants_flush(&self) -> bool {
        if let State::SetKey { .. } = self.state {
            return true;
        }
        false
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.converter.wants_flush() {
            self.converter
                .flush(ctx)
                .await
                .map_err(UniversalHashError::conversion)?;
        }

        if self.wants_flush() {
            let mult_key = self.compute_multiplicative_share()?;

            self.converter
                .flush(ctx)
                .await
                .map_err(UniversalHashError::conversion)?;

            let mult_key = *mult_key
                .await
                .map_err(UniversalHashError::flush)?
                .shares
                .first()
                .expect("Multiplicative key should be present");

            self.state = State::MultKey { key: mult_key };
            let (add_keys, core) = self.compute_additive_shares()?;

            self.converter
                .flush(ctx)
                .await
                .map_err(UniversalHashError::conversion)?;

            let add_keys = add_keys.await.map_err(UniversalHashError::flush)?;
            let core = core.add_new_add_shares(&add_keys.shares);

            self.state = State::Ready { core };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::record_layer::aead::ghash::{Ghash, GhashConfig};
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use mpz_common::{executor::test_st_executor, Flush};
    use mpz_core::Block;
    use mpz_fields::gf2_128::Gf2_128;
    use mpz_share_conversion::ideal::{
        ideal_share_convert, IdealShareConvertReceiver, IdealShareConvertSender,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn create_pair(
        block_count: usize,
    ) -> (
        Ghash<IdealShareConvertSender<Gf2_128>>,
        Ghash<IdealShareConvertReceiver<Gf2_128>>,
    ) {
        let (convert_a, convert_b) = ideal_share_convert(Block::ZERO);

        let config = GhashConfig::builder()
            .block_count(block_count)
            .build()
            .unwrap();

        let (mut sender, mut receiver) = (
            Ghash::new(config.clone(), convert_a),
            Ghash::new(config, convert_b),
        );
        sender.alloc().unwrap();
        receiver.alloc().unwrap();

        (sender, receiver)
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;

        let message: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1);
        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.flush(&mut ctx_a), receiver.flush(&mut ctx_b)).unwrap();

        let sender = sender.finalize().unwrap();
        let receiver = receiver.finalize().unwrap();

        let sender_share = sender.compute(message.clone()).unwrap();
        let receiver_share = receiver.compute(message.clone()).unwrap();

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
        let message: Vec<u8> = (0..14).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1);

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.flush(&mut ctx_a), receiver.flush(&mut ctx_b)).unwrap();

        let sender = sender.finalize().unwrap();
        let receiver = receiver.finalize().unwrap();

        let sender_share = sender.compute(message.clone()).unwrap();
        let receiver_share = receiver.compute(message.clone()).unwrap();

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

        // A longer message.
        let long_message: Vec<u8> = (0..30).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(2);

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.flush(&mut ctx_a), receiver.flush(&mut ctx_b)).unwrap();

        let sender = sender.finalize().unwrap();
        let receiver = receiver.finalize().unwrap();

        let sender_share = sender.compute(long_message.clone()).unwrap();
        let receiver_share = receiver.compute(long_message.clone()).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));
    }

    #[tokio::test]
    async fn test_ghash_repeated() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;

        // Two messages.
        let first_message: Vec<u8> = (0..14).map(|_| rng.gen()).collect();
        let second_message: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(2);

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.flush(&mut ctx_a), receiver.flush(&mut ctx_b)).unwrap();

        let sender = sender.finalize().unwrap();
        let receiver = receiver.finalize().unwrap();

        // Compute and check first message.
        let sender_share = sender.compute(first_message.clone()).unwrap();
        let receiver_share = receiver.compute(first_message.clone()).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &first_message));

        // Compute and check second message.
        let sender_share = sender.compute(second_message.clone()).unwrap();
        let receiver_share = receiver.compute(second_message.clone()).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &second_message));
    }

    fn ghash_reference_impl(h: u128, message: &[u8]) -> Vec<u8> {
        let mut ghash = GhashReference::new(&h.to_be_bytes().into());
        ghash.update_padded(message);
        let mac = ghash.finalize();
        mac.to_vec()
    }
}

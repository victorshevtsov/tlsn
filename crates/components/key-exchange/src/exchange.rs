//! This module implements the key exchange logic.

use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Allocate, Context, Preprocess};

use mpz_fields::{p256::P256, Field};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Memory, MemoryExt, View, ViewExt,
};
use mpz_share_conversion::{ShareConversionError, ShareConvert};
use mpz_vm_core::{CallBuilder, Execute, Vm, VmExt};
use p256::{EncodedPoint, PublicKey, SecretKey};
use serio::{stream::IoStreamExt, SinkExt};
use std::fmt::Debug;
use tracing::{debug, instrument};

use crate::{
    circuit::build_pms_circuit,
    config::{KeyExchangeConfig, Role},
    point_addition::derive_x_coord_share,
    EqualityCheck, KeyExchange, KeyExchangeError, Pms,
};

#[derive(Debug)]
enum State {
    Initialized,
    Setup {
        share_a0: Array<U8, 32>,
        share_b0: Array<U8, 32>,
        share_a1: Array<U8, 32>,
        share_b1: Array<U8, 32>,
        eq: Array<U8, 32>,
    },
    Preprocessed {
        share_a0: Array<U8, 32>,
        share_b0: Array<U8, 32>,
        share_a1: Array<U8, 32>,
        share_b1: Array<U8, 32>,
        eq: Array<U8, 32>,
    },
    Complete,
    Error,
}

impl State {
    fn is_preprocessed(&self) -> bool {
        matches!(self, Self::Preprocessed { .. })
    }

    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// An MPC key exchange protocol.
///
/// Can be either a leader or a follower depending on the `role` field in
/// [`KeyExchangeConfig`].
#[derive(Debug)]
pub struct MpcKeyExchange<C0, C1> {
    /// Share conversion protocol 0.
    converter_0: C0,
    /// Share conversion protocol 1.
    converter_1: C1,
    /// The private key of the party behind this instance, either follower or
    /// leader.
    private_key: Option<SecretKey>,
    /// The public key of the server.
    server_key: Option<PublicKey>,
    /// The config used for the key exchange protocol.
    config: KeyExchangeConfig,
    /// The state of the protocol.
    state: State,
}

impl<C0, C1> MpcKeyExchange<C0, C1> {
    /// Creates a new [`MpcKeyExchange`].
    ///
    /// # Arguments
    ///
    /// * `config` - Key exchange configuration.
    /// * `converter_0` - Share conversion protocol instance 0.
    /// * `converter_1` - Share conversion protocol instance 1.
    pub fn new(config: KeyExchangeConfig, converter_0: C0, converter_1: C1) -> Self {
        Self {
            converter_0,
            converter_1,
            private_key: None,
            server_key: None,
            config,
            state: State::Initialized,
        }
    }
}

impl<C0, C1> MpcKeyExchange<C0, C1> {
    async fn compute_ec_shares<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        server_key: PublicKey,
        private_key: SecretKey,
    ) -> Result<(P256, P256), KeyExchangeError>
    where
        Ctx: Context,
        C0: Allocate
            + Preprocess<Ctx, Error = ShareConversionError>
            + ShareConvert<Ctx, P256>
            + Send,
        C1: Allocate
            + Preprocess<Ctx, Error = ShareConversionError>
            + ShareConvert<Ctx, P256>
            + Send,
    {
        compute_ec_shares(
            ctx,
            self.config.role(),
            &mut self.converter_0,
            &mut self.converter_1,
            server_key,
            private_key,
        )
        .await
    }

    // Computes the PMS using both parties' shares, performing an equality check
    // to ensure the shares are equal.
    async fn compute_pms_with<V>(
        &mut self,
        vm: &mut V,
        share_0: P256,
        share_1: P256,
    ) -> Result<EqualityCheck, KeyExchangeError>
    where
        V: Vm<Binary>,
    {
        let State::Preprocessed {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
        } = self.state.take()
        else {
            return Err(KeyExchangeError::state("not in preprocessed state"));
        };

        let share_0_bytes: [u8; 32] = share_0
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");
        let share_1_bytes: [u8; 32] = share_1
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");

        match self.config.role() {
            Role::Leader => {
                vm.assign(share_a0, share_0_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_a0).map_err(KeyExchangeError::vm)?;

                vm.assign(share_a1, share_1_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_a1).map_err(KeyExchangeError::vm)?;

                vm.commit(share_b0).map_err(KeyExchangeError::vm)?;
                vm.commit(share_b1).map_err(KeyExchangeError::vm)?;
            }
            Role::Follower => {
                vm.assign(share_b0, share_0_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_b0).map_err(KeyExchangeError::vm)?;

                vm.assign(share_b1, share_1_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_b1).map_err(KeyExchangeError::vm)?;

                vm.commit(share_a0).map_err(KeyExchangeError::vm)?;
                vm.commit(share_a1).map_err(KeyExchangeError::vm)?;
            }
        }

        let check = vm.decode(eq).map_err(KeyExchangeError::vm)?;

        Ok(EqualityCheck(check))
    }
}

#[async_trait]
impl<Ctx, V, C0, C1> KeyExchange<Ctx, V> for MpcKeyExchange<C0, C1>
where
    Ctx: Context,
    V: Vm<Binary> + Memory<Binary> + View<Binary> + Execute<Ctx> + Send,
    C0: Allocate + Preprocess<Ctx, Error = ShareConversionError> + ShareConvert<Ctx, P256> + Send,
    C1: Allocate + Preprocess<Ctx, Error = ShareConversionError> + ShareConvert<Ctx, P256> + Send,
{
    fn server_key(&self) -> Option<PublicKey> {
        self.server_key
    }

    async fn set_server_key(
        &mut self,
        ctx: &mut Ctx,
        server_key: PublicKey,
    ) -> Result<(), KeyExchangeError>
    where
        Ctx: Context,
    {
        let Role::Leader = self.config.role() else {
            return Err(KeyExchangeError::role("follower cannot set server key"));
        };

        // Send server public key to follower.
        ctx.io_mut().send(server_key).await?;

        self.server_key = Some(server_key);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    fn setup(&mut self, vm: &mut V) -> Result<Pms, KeyExchangeError> {
        let State::Initialized = self.state.take() else {
            return Err(KeyExchangeError::state("not in initialized state"));
        };

        // 2 A2M, 1 M2A.
        self.converter_0.alloc(3);
        self.converter_1.alloc(3);

        let (share_a0, share_b0, share_a1, share_b1) = match self.config.role() {
            Role::Leader => {
                let share_a0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_a0).map_err(KeyExchangeError::vm)?;

                let share_b0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_b0).map_err(KeyExchangeError::vm)?;

                let share_a1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_a1).map_err(KeyExchangeError::vm)?;

                let share_b1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_b1).map_err(KeyExchangeError::vm)?;

                (share_a0, share_b0, share_a1, share_b1)
            }
            Role::Follower => {
                let share_a0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_a0).map_err(KeyExchangeError::vm)?;

                let share_b0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_b0).map_err(KeyExchangeError::vm)?;

                let share_a1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_a1).map_err(KeyExchangeError::vm)?;

                let share_b1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_b1).map_err(KeyExchangeError::vm)?;

                (share_a0, share_b0, share_a1, share_b1)
            }
        };

        let pms_circuit = build_pms_circuit();
        let pms_call = CallBuilder::new(pms_circuit)
            .arg(share_a0)
            .arg(share_b0)
            .arg(share_a1)
            .arg(share_b1)
            .build()
            .map_err(KeyExchangeError::vm)?;

        let (pms, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
            vm.call(pms_call).map_err(KeyExchangeError::vm)?;

        self.state = State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
        };

        Ok(Pms::new(pms))
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), KeyExchangeError> {
        let State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
        } = self.state.take()
        else {
            return Err(KeyExchangeError::state("not in setup state"));
        };

        // Preprocess share conversion.
        ctx.try_join(
            |ctx| self.converter_0.preprocess(ctx).scope_boxed(),
            |ctx| self.converter_1.preprocess(ctx).scope_boxed(),
        )
        .await??;

        // Follower can forward their key share immediately.
        if let Role::Follower = self.config.role() {
            let private_key = self
                .private_key
                .get_or_insert_with(|| SecretKey::random(&mut rand::rngs::OsRng));

            ctx.io_mut().send(private_key.public_key()).await?;

            debug!("sent public key share to leader");
        }

        self.state = State::Preprocessed {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
        };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn client_key(&mut self, ctx: &mut Ctx) -> Result<PublicKey, KeyExchangeError> {
        if let Role::Leader = self.config.role() {
            let private_key = self
                .private_key
                .get_or_insert_with(|| SecretKey::random(&mut rand::rngs::OsRng));
            let public_key = private_key.public_key();

            // Receive public key share from follower.
            let follower_public_key: PublicKey = ctx.io_mut().expect_next().await?;

            debug!("received public key share from follower");

            // Combine public keys.
            let client_public_key = PublicKey::from_affine(
                (public_key.to_projective() + follower_public_key.to_projective()).to_affine(),
            )?;

            Ok(client_public_key)
        } else {
            Err(KeyExchangeError::role("follower does not learn client key"))
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_pms(
        &mut self,
        ctx: &mut Ctx,
        vm: &mut V,
    ) -> Result<EqualityCheck, KeyExchangeError> {
        if !self.state.is_preprocessed() {
            return Err(KeyExchangeError::state("not in preprocessed state"));
        }

        let server_key = match self.config.role() {
            Role::Leader => self
                .server_key
                .ok_or_else(|| KeyExchangeError::state("server public key not set"))?,
            Role::Follower => {
                // Receive server public key from leader.
                let server_key = ctx.io_mut().expect_next().await?;

                self.server_key = Some(server_key);

                server_key
            }
        };

        let private_key = self
            .private_key
            .take()
            .ok_or(KeyExchangeError::state("private key not set"))?;

        let (pms_share_0, pms_share_1) =
            self.compute_ec_shares(ctx, server_key, private_key).await?;
        let check = self.compute_pms_with(vm, pms_share_0, pms_share_1).await?;

        self.state = State::Complete;

        Ok(check)
    }
}

async fn compute_ec_shares<
    Ctx: Context,
    C0: ShareConvert<Ctx, P256> + Send,
    C1: ShareConvert<Ctx, P256> + Send,
>(
    ctx: &mut Ctx,
    role: Role,
    converter_0: &mut C0,
    converter_1: &mut C1,
    server_key: PublicKey,
    private_key: SecretKey,
) -> Result<(P256, P256), KeyExchangeError> {
    // Compute the leader's/follower's share of the pre-master secret.
    //
    // We need to mimic the [diffie-hellman](p256::ecdh::diffie_hellman) function
    // without the [SharedSecret](p256::ecdh::SharedSecret) wrapper, because
    // this makes it harder to get the result as an EC curve point.
    let shared_secret = {
        let public_projective = server_key.to_projective();
        (public_projective * private_key.to_nonzero_scalar().as_ref()).to_affine()
    };

    let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);

    let (pms_share_0, pms_share_1) = ctx
        .try_join(
            |ctx| {
                async { derive_x_coord_share(role, ctx, converter_0, encoded_point).await }
                    .scope_boxed()
            },
            |ctx| {
                async { derive_x_coord_share(role, ctx, converter_1, encoded_point).await }
                    .scope_boxed()
            },
        )
        .await??;

    Ok((pms_share_0, pms_share_1))
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorRepr;

    use super::*;

    use mpz_common::executor::{test_st_executor, TestSTExecutor};
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::{ideal_cot_with_delta, IdealCOTReceiver, IdealCOTSender};
    use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand::rngs::StdRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key.clone());
        follower.private_key = Some(follower_private_key.clone());

        KeyExchange::<TestSTExecutor, _>::setup(&mut leader, &mut gen).unwrap();
        KeyExchange::<TestSTExecutor, _>::setup(&mut follower, &mut ev).unwrap();
        tokio::try_join!(
            KeyExchange::<_, Generator<IdealCOTSender>>::preprocess(&mut leader, &mut ctx_a),
            KeyExchange::<_, Evaluator<IdealCOTReceiver>>::preprocess(&mut follower, &mut ctx_b),
        )
        .unwrap();

        let client_public_key =
            KeyExchange::<_, Generator<IdealCOTSender>>::client_key(&mut leader, &mut ctx_a)
                .await
                .unwrap();
        KeyExchange::<_, Generator<IdealCOTSender>>::set_server_key(
            &mut leader,
            &mut ctx_a,
            server_public_key,
        )
        .await
        .unwrap();

        let expected_client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key);
        follower.private_key = Some(follower_private_key);

        tokio::try_join!(
            async {
                KeyExchange::<TestSTExecutor, _>::setup(&mut leader, &mut gen).unwrap();
                KeyExchange::<_, Generator<IdealCOTSender>>::preprocess(&mut leader, &mut ctx_a)
                    .await
                    .unwrap();

                KeyExchange::<_, Generator<IdealCOTSender>>::set_server_key(
                    &mut leader,
                    &mut ctx_a,
                    server_public_key,
                )
                .await
                .unwrap();

                let check = leader.compute_pms(&mut ctx_a, &mut gen).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
                check.check().await
            },
            async {
                KeyExchange::<TestSTExecutor, _>::setup(&mut follower, &mut ev).unwrap();
                KeyExchange::<_, Evaluator<IdealCOTReceiver>>::preprocess(
                    &mut follower,
                    &mut ctx_b,
                )
                .await
                .unwrap();
                let check = follower.compute_pms(&mut ctx_b, &mut ev).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
                check.check().await
            }
        )
        .unwrap();

        assert_eq!(leader.server_key.unwrap(), server_public_key);
        assert_eq!(follower.server_key.unwrap(), server_public_key);
    }

    #[tokio::test]
    async fn test_compute_ec_shares() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_leader, mut ctx_follower) = test_st_executor(8);
        let (mut leader_converter_0, mut follower_converter_0) = ideal_share_converter();
        let (mut follower_converter_1, mut leader_converter_1) = ideal_share_converter();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        let ((leader_share_0, leader_share_1), (follower_share_0, follower_share_1)) =
            tokio::try_join!(
                compute_ec_shares(
                    &mut ctx_leader,
                    Role::Leader,
                    &mut leader_converter_0,
                    &mut leader_converter_1,
                    server_public_key,
                    leader_private_key
                ),
                compute_ec_shares(
                    &mut ctx_follower,
                    Role::Follower,
                    &mut follower_converter_0,
                    &mut follower_converter_1,
                    server_public_key,
                    follower_private_key
                )
            )
            .unwrap();

        let expected_ecdh_x =
            p256::ecdh::diffie_hellman(server_private_key, client_public_key.as_affine());

        assert_eq!(
            (leader_share_0 + follower_share_0).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );
        assert_eq!(
            (leader_share_1 + follower_share_1).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );

        assert_ne!(leader_share_0, follower_share_0);
        assert_ne!(leader_share_1, follower_share_1);
    }

    #[tokio::test]
    async fn test_compute_pms_fail() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key.clone());
        follower.private_key = Some(follower_private_key.clone());

        KeyExchange::<TestSTExecutor, _>::setup(&mut leader, &mut gen).unwrap();
        KeyExchange::<TestSTExecutor, _>::setup(&mut follower, &mut ev).unwrap();
        tokio::try_join!(
            KeyExchange::<_, Generator<IdealCOTSender>>::preprocess(&mut leader, &mut ctx_a),
            KeyExchange::<_, Evaluator<IdealCOTReceiver>>::preprocess(&mut follower, &mut ctx_b),
        )
        .unwrap();

        KeyExchange::<_, Generator<IdealCOTSender>>::set_server_key(
            &mut leader,
            &mut ctx_a,
            server_public_key,
        )
        .await
        .unwrap();

        let ((mut share_a0, share_a1), (share_b0, share_b1)) = tokio::try_join!(
            leader.compute_ec_shares(&mut ctx_a, server_public_key, leader_private_key),
            follower.compute_ec_shares(&mut ctx_b, server_public_key, follower_private_key)
        )
        .unwrap();

        share_a0 = share_a0 + P256::one();

        let (check_leader, check_follower) = tokio::try_join!(
            leader.compute_pms_with(&mut gen, share_a0, share_a1),
            follower.compute_pms_with(&mut ev, share_b0, share_b1)
        )
        .unwrap();

        let (leader_res, follower_res) = tokio::join!(
            async {
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                check_leader.check().await
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                check_follower.check().await
            }
        );

        let leader_err = leader_res.unwrap_err();
        let follower_err = follower_res.unwrap_err();

        assert!(matches!(leader_err.kind(), ErrorRepr::ShareConversion(_)));
        assert!(matches!(follower_err.kind(), ErrorRepr::ShareConversion(_)));
    }

    #[tokio::test]
    async fn test_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (gen, ev) = mock_vm();

        let share_a0_bytes = [5_u8; 32];
        let share_a1_bytes = [2_u8; 32];

        let share_b0_bytes = [3_u8; 32];
        let share_b1_bytes = [6_u8; 32];

        let (res_gen, res_ev) = tokio::join!(
            async move {
                let mut vm = gen;
                let share_a0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_a0).unwrap();

                let share_b0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_b0).unwrap();

                let share_a1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_a1).unwrap();

                let share_b1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_b1).unwrap();

                let pms_circuit = build_pms_circuit();
                let pms_call = CallBuilder::new(pms_circuit)
                    .arg(share_a0)
                    .arg(share_b0)
                    .arg(share_a1)
                    .arg(share_b1)
                    .build()
                    .unwrap();

                let (_, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
                    vm.call(pms_call).unwrap();

                vm.assign(share_a0, share_a0_bytes).unwrap();
                vm.commit(share_a0).unwrap();

                vm.assign(share_a1, share_a1_bytes).unwrap();
                vm.commit(share_a1).unwrap();

                vm.commit(share_b0).unwrap();
                vm.commit(share_b1).unwrap();

                let check = vm.decode(eq).unwrap();

                vm.flush(&mut ctx_a).await.unwrap();
                vm.execute(&mut ctx_a).await.unwrap();
                vm.flush(&mut ctx_a).await.unwrap();
                check.await
            },
            async {
                let mut vm = ev;
                let share_a0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_a0).unwrap();

                let share_b0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_b0).unwrap();

                let share_a1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_a1).unwrap();

                let share_b1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_b1).unwrap();

                let pms_circuit = build_pms_circuit();
                let pms_call = CallBuilder::new(pms_circuit)
                    .arg(share_a0)
                    .arg(share_b0)
                    .arg(share_a1)
                    .arg(share_b1)
                    .build()
                    .unwrap();

                let (_, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
                    vm.call(pms_call).unwrap();

                vm.assign(share_b0, share_b0_bytes).unwrap();
                vm.commit(share_b0).unwrap();

                vm.assign(share_b1, share_b1_bytes).unwrap();
                vm.commit(share_b1).unwrap();

                vm.commit(share_a0).unwrap();
                vm.commit(share_a1).unwrap();

                let check = vm.decode(eq).unwrap();

                vm.flush(&mut ctx_b).await.unwrap();
                vm.execute(&mut ctx_b).await.unwrap();
                vm.flush(&mut ctx_b).await.unwrap();
                check.await
            }
        );

        let res_gen = res_gen.unwrap();
        let res_ev = res_ev.unwrap();

        assert_eq!(res_gen, res_ev);
        assert_eq!(res_gen, [0_u8; 32]);
    }

    fn create_pair() -> (
        MpcKeyExchange<IdealShareConverter, IdealShareConverter>,
        MpcKeyExchange<IdealShareConverter, IdealShareConverter>,
    ) {
        let (leader_converter_0, follower_converter_0) = ideal_share_converter();
        let (follower_converter_1, leader_converter_1) = ideal_share_converter();

        let leader = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Leader)
                .build()
                .unwrap(),
            leader_converter_0,
            leader_converter_1,
        );

        let follower = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Follower)
                .build()
                .unwrap(),
            follower_converter_0,
            follower_converter_1,
        );

        (leader, follower)
    }

    fn mock_vm() -> (Generator<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }
}

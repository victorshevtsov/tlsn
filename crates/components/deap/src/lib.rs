use std::mem;

use async_trait::async_trait;
use mpz_common::{scoped, Context, ContextError};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{binary::Binary, DecodeFuture, Memory, Slice, View},
    Call, Execute, Vm,
};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};

type Error = DeapError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Leader,
    Follower,
}

#[derive(Debug, Serialize, Deserialize)]
struct FollowerReveal {
    data: BitVec,
}

/// DEAP Vm.
#[derive(Debug)]
pub struct Deap<Mpc, Zk> {
    role: Role,
    mpc: Mpc,
    zk: Zk,
    /// Private inputs of the follower.
    follower_inputs: Vec<Slice>,
    outputs: Vec<(Slice, DecodeFuture<BitVec>)>,
}

impl<Mpc, Zk> Deap<Mpc, Zk> {
    /// Create a new DEAP Vm.
    pub fn new(role: Role, mpc: Mpc, zk: Zk) -> Self {
        Self {
            role,
            mpc,
            zk,
            follower_inputs: Vec::default(),
            outputs: Vec::default(),
        }
    }

    /// Returns the MPC and ZK VMs.
    pub fn into_inner(self) -> (Mpc, Zk) {
        (self.mpc, self.zk)
    }
}

impl<Mpc, Zk> Deap<Mpc, Zk>
where
    Mpc: Memory<Binary>,
    Zk: Memory<Binary>,
{
    /// Finalize the DEAP Vm.
    ///
    /// This reveals all private inputs of the follower.
    pub async fn finalize<Ctx: Context>(&mut self, ctx: &mut Ctx) -> Result<()>
    where
        Zk: Execute<Ctx>,
    {
        match self.role {
            Role::Leader => {
                // Receive the private inputs from the follower.
                let FollowerReveal { data } = ctx.io_mut().expect_next().await.unwrap();

                let expected_len = self.follower_inputs.iter().map(|input| input.len()).sum();
                if data.len() != expected_len {
                    todo!()
                }

                let mut i = 0;
                for input in mem::take(&mut self.follower_inputs) {
                    let data = data[i..i + input.len()].to_bitvec();
                    i += input.len();

                    self.zk.assign_raw(input, data).map_err(Error::zk)?;
                    self.zk.commit_raw(input).map_err(Error::zk)?;
                }

                self.zk.flush(ctx).await.map_err(Error::zk)?;
                self.zk.execute(ctx).await.map_err(Error::zk)?;
                self.zk.flush(ctx).await.map_err(Error::zk)?;
            }
            Role::Follower => {
                let mut input_data = BitVec::new();
                for input in mem::take(&mut self.follower_inputs) {
                    let data = self.mpc.get_raw(input).map_err(Error::mpc)?.unwrap();
                    input_data.extend_from_bitslice(&data);

                    self.zk.commit_raw(input).map_err(Error::zk)?;
                }

                // Send the private inputs to the leader.
                ctx.io_mut()
                    .send(FollowerReveal { data: input_data })
                    .await
                    .unwrap();

                self.zk.flush(ctx).await.map_err(Error::zk)?;
                self.zk.execute(ctx).await.map_err(Error::zk)?;
                self.zk.flush(ctx).await.map_err(Error::zk)?;

                for (output, mut data) in mem::take(&mut self.outputs) {
                    let zk_output = data.try_recv().map_err(Error::zk)?.unwrap();
                    let mpc_output = self.mpc.get_raw(output).map_err(Error::mpc)?.unwrap();

                    if zk_output != mpc_output {
                        todo!()
                    }
                }
            }
        }

        Ok(())
    }
}

impl<Mpc, Zk> Memory<Binary> for Deap<Mpc, Zk>
where
    Mpc: Memory<Binary>,
    Zk: Memory<Binary>,
{
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.zk.alloc_raw(size).map_err(Error::zk)?;
        self.mpc.alloc_raw(size).map_err(Error::mpc)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.zk.assign_raw(slice, data.clone()).map_err(Error::zk)?;
        self.mpc.assign_raw(slice, data).map_err(Error::mpc)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        // Follower's private inputs are not committed in the ZK VM until finalization.
        if !self.follower_inputs.contains(&slice) {
            self.zk.commit_raw(slice).map_err(Error::zk)?;
        }

        self.mpc.commit_raw(slice).map_err(Error::mpc)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.mpc.get_raw(slice).map_err(Error::mpc)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.outputs
            .push((slice, self.zk.decode_raw(slice).map_err(Error::zk)?));

        self.mpc.decode_raw(slice).map_err(Error::mpc)
    }
}

impl<Mpc, Zk> View<Binary> for Deap<Mpc, Zk>
where
    Mpc: View<Binary>,
    Zk: View<Binary>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.zk.mark_public_raw(slice).map_err(Error::zk)?;
        self.mpc.mark_public_raw(slice).map_err(Error::mpc)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        match self.role {
            Role::Leader => {
                self.zk.mark_private_raw(slice).map_err(Error::zk)?;
                self.mpc.mark_private_raw(slice).map_err(Error::mpc)?;
            }
            Role::Follower => {
                // Follower's private inputs will become public during finalization.
                self.zk.mark_public_raw(slice).map_err(Error::zk)?;
                self.mpc.mark_private_raw(slice).map_err(Error::mpc)?;
                self.follower_inputs.push(slice);
            }
        }

        Ok(())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        match self.role {
            Role::Leader => {
                // Follower's private inputs will become public during finalization.
                self.zk.mark_public_raw(slice).map_err(Error::zk)?;
                self.mpc.mark_blind_raw(slice).map_err(Error::mpc)?;
                self.follower_inputs.push(slice);
            }
            Role::Follower => {
                self.zk.mark_blind_raw(slice).map_err(Error::zk)?;
                self.mpc.mark_blind_raw(slice).map_err(Error::mpc)?;
            }
        }

        Ok(())
    }
}

impl<Mpc, Zk> Vm<Binary> for Deap<Mpc, Zk>
where
    Mpc: Vm<Binary>,
    Zk: Vm<Binary>,
{
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        self.zk.call_raw(call.clone()).map_err(Error::zk)?;
        self.mpc.call_raw(call).map_err(Error::mpc)
    }
}

#[async_trait]
impl<Ctx, Mpc, Zk> Execute<Ctx> for Deap<Mpc, Zk>
where
    Ctx: Context + Send,
    Mpc: Execute<Ctx> + Send,
    Zk: Execute<Ctx> + Send,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        let zk = &mut self.zk;
        let mpc = &mut self.mpc;
        ctx.try_join(
            scoped!(|ctx| zk.flush(ctx).await.map_err(Error::zk)),
            scoped!(|ctx| mpc.flush(ctx).await.map_err(Error::mpc)),
        )
        .await??;

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        let zk = &mut self.zk;
        let mpc = &mut self.mpc;
        ctx.try_join(
            scoped!(|ctx| zk.preprocess(ctx).await.map_err(Error::zk)),
            scoped!(|ctx| mpc.preprocess(ctx).await.map_err(Error::mpc)),
        )
        .await??;

        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
        // Only MPC VM is executed until finalization.
        self.mpc.execute(ctx).await.map_err(Error::mpc)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DeapError(#[from] ErrorRepr);

impl DeapError {
    fn mpc<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Mpc(err.into()))
    }

    fn zk<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Zk(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("MPC error: {0}")]
    Mpc(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("ZK error: {0}")]
    Zk(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("context error: {0}")]
    Context(#[from] ContextError),
}

impl From<ContextError> for DeapError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::executor::test_st_executor;
    use mpz_core::Block;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_ot::ideal::{cot::ideal_cot_with_delta, rcot::ideal_rcot};
    use mpz_vm_core::{
        memory::{binary::U8, correlated::Delta, Array},
        prelude::*,
    };
    use mpz_zk::{Prover, Verifier};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_deap() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta.into_inner());
        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let gb = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta, rcot_send);

        let mut leader = Deap::new(Role::Leader, gb, prover);
        let mut follower = Deap::new(Role::Follower, ev, verifier);

        let (ct_leader, ct_follower) = futures::join!(
            async {
                let key: Array<U8, 16> = leader.alloc().unwrap();
                let msg: Array<U8, 16> = leader.alloc().unwrap();

                leader.mark_private(key).unwrap();
                leader.mark_blind(msg).unwrap();
                leader.assign(key, [42u8; 16]).unwrap();
                leader.commit(key).unwrap();
                leader.commit(msg).unwrap();

                let ct: Array<U8, 16> = leader
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();
                let ct = leader.decode(ct).unwrap();

                leader.flush(&mut ctx_a).await.unwrap();
                leader.execute(&mut ctx_a).await.unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
                leader.finalize(&mut ctx_a).await.unwrap();

                ct.await.unwrap()
            },
            async {
                let key: Array<U8, 16> = follower.alloc().unwrap();
                let msg: Array<U8, 16> = follower.alloc().unwrap();

                follower.mark_blind(key).unwrap();
                follower.mark_private(msg).unwrap();
                follower.assign(msg, [69u8; 16]).unwrap();
                follower.commit(key).unwrap();
                follower.commit(msg).unwrap();

                let ct: Array<U8, 16> = follower
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();
                let ct = follower.decode(ct).unwrap();

                follower.flush(&mut ctx_b).await.unwrap();
                follower.execute(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
                follower.finalize(&mut ctx_b).await.unwrap();

                ct.await.unwrap()
            }
        );

        assert_eq!(ct_leader, ct_follower);
    }
}

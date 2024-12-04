use crate::{
    follower::{Closed, MpcTlsFollower, MpcTlsFollowerData},
    msg::{
        follower::MpcTlsFollowerMsg, ClientFinishedVd, CloseConnection, Commit, CommitMessage,
        ComputeKeyExchange, DecryptAlert, DecryptMessage, DecryptServerFinished, EncryptAlert,
        EncryptClientFinished, EncryptMessage, ServerFinishedVd,
    },
    MpcTlsError,
};
use cipher::{aes::Aes128, Cipher};
use futures::{FutureExt, StreamExt};
use hmac_sha256::Prf;
use key_exchange::KeyExchange;
use ludi::{Address, Dispatch, Handler, Message};
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{binary::Binary, Memory, View};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use std::future::Future;
use tracing::{debug, Instrument};

#[derive(Clone)]
pub struct MpcTlsFollowerCtrl {
    address: Address<MpcTlsFollowerMsg>,
}

impl MpcTlsFollowerCtrl {
    /// Creates a new control for [`MpcTlsFollower`].
    pub fn new(address: Address<MpcTlsFollowerMsg>) -> Self {
        Self { address }
    }
}

impl<K, P, C, Sc, Ctx, V> ludi::Actor for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    type Stop = MpcTlsFollowerData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("follower actor stopped");

        let Closed { server_key } = self.state.take().try_into_closed()?;

        let bytes_sent = self.encrypter.sent_bytes();
        let bytes_recv = self.decrypter.recv_bytes();

        Ok(MpcTlsFollowerData {
            server_key,
            bytes_sent,
            bytes_recv,
        })
    }
}

impl<K, P, C, Sc, Ctx, V> MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    /// Runs the follower actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is
    /// stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(
        mut self,
    ) -> (
        MpcTlsFollowerCtrl,
        impl Future<Output = Result<MpcTlsFollowerData, MpcTlsError>>,
    ) {
        let (mut mailbox, addr) = ludi::mailbox::<MpcTlsFollowerMsg>(100);
        let ctrl = MpcTlsFollowerCtrl::new(addr);
        let ctrl_fut = ctrl.clone();

        let mut stream = self
            .stream
            .take()
            .expect("stream should be present from constructor");

        let mut remote_fut = Box::pin(async move {
            while let Some(msg) = stream.next().await {
                let msg = MpcTlsFollowerMsg::try_from(msg?)?;
                ctrl_fut.address.send(msg).await?;
            }

            Ok::<_, MpcTlsError>(())
        })
        .fuse();

        let mut actor_fut =
            Box::pin(async move { ludi::run(&mut self, &mut mailbox).await }).fuse();

        let fut = async move {
            loop {
                futures::select! {
                    res = &mut remote_fut => {
                        res?;
                    },
                    res = &mut actor_fut => return res,
                }
            }
        };

        (ctrl, fut.in_current_span())
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for ComputeKeyExchange
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<ComputeKeyExchange> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn handle(
        &mut self,
        msg: ComputeKeyExchange,
        ctx: &mut ludi::Context<Self>,
    ) -> impl std::future::Future<Output = <ComputeKeyExchange as Message>::Return> + Send {
        let ComputeKeyExchange { server_random } = msg;

        async move {
            ctx.try_or_stop(|_| self.compute_key_exchange(server_random))
                .await
        }
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for ClientFinishedVd
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<ClientFinishedVd> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: ClientFinishedVd,
        ctx: &mut ludi::Context<Self>,
    ) -> <ClientFinishedVd as Message>::Return {
        ctx.try_or_stop(|_| self.client_finished_vd(msg.handshake_hash))
            .await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for ServerFinishedVd
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<ServerFinishedVd> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: ServerFinishedVd,
        ctx: &mut ludi::Context<Self>,
    ) -> <ServerFinishedVd as Message>::Return {
        ctx.try_or_stop(|_| self.server_finished_vd(msg.handshake_hash))
            .await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for EncryptClientFinished
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<EncryptClientFinished> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        _msg: EncryptClientFinished,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptClientFinished as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_client_finished()).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for EncryptAlert
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<EncryptAlert> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: EncryptAlert,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptAlert as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_alert(msg.msg)).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for EncryptMessage
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<EncryptMessage> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: EncryptMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptMessage as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_message(msg.len)).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for DecryptServerFinished
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<DecryptServerFinished> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: DecryptServerFinished,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptServerFinished as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_server_finished(msg.ciphertext))
            .await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for DecryptAlert
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<DecryptAlert> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: DecryptAlert,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptAlert as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_alert(msg.ciphertext))
            .await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for CommitMessage
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<CommitMessage> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        msg: CommitMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <CommitMessage as Message>::Return {
        ctx.try_or_stop(|_| async { self.commit_message(msg.msg) })
            .await;
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for DecryptMessage
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<DecryptMessage> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        _msg: DecryptMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptMessage as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_message()).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for CloseConnection
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<CloseConnection> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        _msg: CloseConnection,
        ctx: &mut ludi::Context<Self>,
    ) -> <CloseConnection as Message>::Return {
        ctx.try_or_stop(|_| async { self.close_connection() }).await;
        ctx.stop();
        Some(())
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsFollower<K, P, C, Sc, Ctx, V>> for Commit
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower<K, P, C, Sc, Ctx, V>,
        ctx: &mut ludi::Context<MpcTlsFollower<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<Commit> for MpcTlsFollower<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn handle(
        &mut self,
        _msg: Commit,
        ctx: &mut ludi::Context<Self>,
    ) -> <Commit as Message>::Return {
        ctx.try_or_stop(|_| async { self.commit().await }).await
    }
}

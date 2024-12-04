use crate::{
    leader::{state, MpcTlsData, MpcTlsLeader},
    msg::leader::{
        BackendMsgBufferIncoming, BackendMsgBufferLen, BackendMsgDecrypt, BackendMsgEncrypt,
        BackendMsgGetClientFinishedVd, BackendMsgGetClientKeyShare, BackendMsgGetClientRandom,
        BackendMsgGetNotify, BackendMsgGetServerFinishedVd, BackendMsgGetSuite,
        BackendMsgNextIncoming, BackendMsgPrepareEncryption, BackendMsgServerClosed,
        BackendMsgSetCipherSuite, BackendMsgSetDecrypt, BackendMsgSetEncrypt,
        BackendMsgSetHsHashClientKeyExchange, BackendMsgSetHsHashServerHello,
        BackendMsgSetProtocolVersion, BackendMsgSetServerCertDetails, BackendMsgSetServerKeyShare,
        BackendMsgSetServerKxDetails, BackendMsgSetServerRandom, CloseConnection, Commit,
        DeferDecryption, MpcTlsLeaderMsg,
    },
    MpcTlsError,
};
use async_trait::async_trait;
use cipher::{aes::Aes128, Cipher};
use hmac_sha256::Prf;
use key_exchange::KeyExchange;
use ludi::{mailbox, Actor, Address, Context as LudiCtx, Dispatch, Handler, Message};
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{binary::Binary, Memory, View};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use std::future::Future;
use tls_backend::{Backend, BackendError, BackendNotify, DecryptMode, EncryptMode};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::ProtocolVersion,
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tracing::{debug, Instrument};

#[derive(Clone)]
pub struct MpcTlsLeaderCtrl {
    address: Address<MpcTlsLeaderMsg>,
}

impl MpcTlsLeaderCtrl {
    /// Creates a new control for [`MpcTlsLeader`].
    pub fn new(address: Address<MpcTlsLeaderMsg>) -> Self {
        Self { address }
    }
}

impl<K, P, C, Sc, Ctx, V> MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
    /// Runs the leader actor.
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
        MpcTlsLeaderCtrl,
        impl Future<Output = Result<MpcTlsData, MpcTlsError>>,
    ) {
        let (mut mailbox, address) = mailbox(100);

        let ctrl = MpcTlsLeaderCtrl::new(address);
        let fut = async move { ludi::run(&mut self, &mut mailbox).await };

        (ctrl, fut.in_current_span())
    }
}

impl<K, P, C, Sc, Ctx, V> Actor for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
    type Stop = MpcTlsData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("leader actor stopped");

        let state::Closed { data } = self.state.take().try_into_closed()?;

        Ok(data)
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for MpcTlsLeaderMsg
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
    async fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) {
        match self {
            MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetProtocolVersion(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetCipherSuite(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetCipherSuite(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetSuite(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetSuite(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetEncrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetEncrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetDecrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetDecrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientRandom(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientRandom(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientKeyShare(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerRandom(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerRandom(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerKeyShare(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerCertDetails(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerKxDetails(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetHsHashClientKeyExchange(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetHsHashServerHello(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetServerFinishedVd(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientFinishedVd(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgPrepareEncryption(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgPrepareEncryption(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgEncrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgEncrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgDecrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgDecrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgNextIncoming(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgNextIncoming(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgBufferIncoming(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgBufferIncoming(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetNotify(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetNotify(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgBufferLen(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgBufferLen(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgServerClosed(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgServerClosed(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::DeferDecryption(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::DeferDecryption(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::CloseConnection(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::CloseConnection(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::Finalize(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::Finalize(value)))
                    .await;
            }
        }
    }
}

#[async_trait]
impl Backend for MpcTlsLeaderCtrl {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetProtocolVersion { version })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetCipherSuite { suite })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        self.address
            .send(BackendMsgGetSuite)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetEncrypt { mode })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetDecrypt { mode })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        self.address
            .send(BackendMsgGetClientRandom)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        self.address
            .send(BackendMsgGetClientKeyShare)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerRandom { random })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerKeyShare { key })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerCertDetails { cert_details })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerKxDetails { kx_details })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetHsHashClientKeyExchange { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetHsHashServerHello { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.address
            .send(BackendMsgGetServerFinishedVd { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.address
            .send(BackendMsgGetClientFinishedVd { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgPrepareEncryption)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        self.address
            .send(BackendMsgEncrypt { msg, seq })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        self.address
            .send(BackendMsgDecrypt { msg, seq })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgBufferIncoming { msg })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        self.address
            .send(BackendMsgNextIncoming)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        self.address
            .send(BackendMsgGetNotify)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn buffer_len(&mut self) -> Result<usize, BackendError> {
        self.address
            .send(BackendMsgBufferLen)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgServerClosed)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }
}

impl MpcTlsLeaderCtrl {
    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&self) -> Result<(), MpcTlsError> {
        self.address
            .send(DeferDecryption)
            .await
            .map_err(MpcTlsError::io)?
    }

    /// Closes the connection.
    pub async fn close_connection(&self) -> Result<(), MpcTlsError> {
        self.address
            .send(CloseConnection)
            .await
            .map_err(MpcTlsError::io)?
    }

    /// Commits the leader to the current transcript.
    ///
    /// This reveals the AEAD key to the leader and disables sending or
    /// receiving any further messages.
    pub async fn commit(&self) -> Result<(), MpcTlsError> {
        self.address.send(Commit).await.map_err(MpcTlsError::io)?
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetProtocolVersion
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetProtocolVersion>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetProtocolVersion,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetProtocolVersion as Message>::Return {
        self.set_protocol_version(msg.version).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgSetCipherSuite
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetCipherSuite> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetCipherSuite,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetCipherSuite as Message>::Return {
        self.set_cipher_suite(msg.suite).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgGetSuite
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetSuite> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgGetSuite,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetSuite as Message>::Return {
        self.get_suite().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgSetEncrypt
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetEncrypt> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetEncrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetEncrypt as Message>::Return {
        self.set_encrypt(msg.mode).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgSetDecrypt
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetDecrypt> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetDecrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetDecrypt as Message>::Return {
        self.set_decrypt(msg.mode).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgGetClientRandom
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetClientRandom> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgGetClientRandom,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientRandom as Message>::Return {
        self.get_client_random().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgGetClientKeyShare
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetClientKeyShare> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgGetClientKeyShare,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientKeyShare as Message>::Return {
        self.get_client_key_share().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgSetServerRandom
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetServerRandom> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetServerRandom,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerRandom as Message>::Return {
        self.set_server_random(msg.random).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetServerKeyShare
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetServerKeyShare> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetServerKeyShare,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerKeyShare as Message>::Return {
        self.set_server_key_share(msg.key).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetServerCertDetails
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetServerCertDetails>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetServerCertDetails,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerCertDetails as Message>::Return {
        self.set_server_cert_details(msg.cert_details).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetServerKxDetails
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetServerKxDetails>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetServerKxDetails,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerKxDetails as Message>::Return {
        self.set_server_kx_details(msg.kx_details).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetHsHashClientKeyExchange
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetHsHashClientKeyExchange>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetHsHashClientKeyExchange,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetHsHashClientKeyExchange as Message>::Return {
        self.set_hs_hash_client_key_exchange(msg.hash).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgSetHsHashServerHello
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgSetHsHashServerHello>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgSetHsHashServerHello,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetHsHashServerHello as Message>::Return {
        self.set_hs_hash_server_hello(msg.hash).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgGetServerFinishedVd
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetServerFinishedVd>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgGetServerFinishedVd,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetServerFinishedVd as Message>::Return {
        self.get_server_finished_vd(msg.hash).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgGetClientFinishedVd
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetClientFinishedVd>
    for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgGetClientFinishedVd,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientFinishedVd as Message>::Return {
        self.get_client_finished_vd(msg.hash).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>>
    for BackendMsgPrepareEncryption
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgPrepareEncryption> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgPrepareEncryption,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgPrepareEncryption as Message>::Return {
        self.prepare_encryption().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgEncrypt
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgEncrypt> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgEncrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgEncrypt as Message>::Return {
        self.encrypt(msg.msg, msg.seq).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgDecrypt
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgDecrypt> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgDecrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgDecrypt as Message>::Return {
        self.decrypt(msg.msg, msg.seq).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgBufferIncoming
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgBufferIncoming> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        msg: BackendMsgBufferIncoming,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgBufferIncoming as Message>::Return {
        self.buffer_incoming(msg.msg).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgNextIncoming
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgNextIncoming> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgNextIncoming,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgNextIncoming as Message>::Return {
        self.next_incoming().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgGetNotify
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgGetNotify> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgGetNotify,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetNotify as Message>::Return {
        self.get_notify().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgBufferLen
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgBufferLen> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgBufferLen,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgBufferLen as Message>::Return {
        self.buffer_len().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for BackendMsgServerClosed
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<BackendMsgServerClosed> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: BackendMsgServerClosed,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgServerClosed as Message>::Return {
        self.server_closed().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for DeferDecryption
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<DeferDecryption> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _msg: DeferDecryption,
        _ctx: &mut LudiCtx<Self>,
    ) -> <DeferDecryption as Message>::Return {
        self.defer_decryption().await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for CloseConnection
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<CloseConnection> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        ctx: &mut LudiCtx<Self>,
    ) -> <CloseConnection as Message>::Return {
        self.close_connection(ctx).await
    }
}

impl<K, P, C, Sc, Ctx, V> Dispatch<MpcTlsLeader<K, P, C, Sc, Ctx, V>> for Commit
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
        actor: &mut MpcTlsLeader<K, P, C, Sc, Ctx, V>,
        ctx: &mut LudiCtx<MpcTlsLeader<K, P, C, Sc, Ctx, V>>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl<K, P, C, Sc, Ctx, V> Handler<Commit> for MpcTlsLeader<K, P, C, Sc, Ctx, V>
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
        _ctx: &mut LudiCtx<Self>,
    ) -> <Commit as Message>::Return {
        self.commit().await
    }
}

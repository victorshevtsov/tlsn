use crate::{
    decode::Decode,
    error::MpcTlsError,
    msg::{
        ClientFinishedVd, CloseConnection, Commit, CommitMessage, ComputeKeyExchange, DecryptAlert,
        DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
        MpcTlsMessage, ServerFinishedVd,
    },
    record_layer::{aead::transmute, Decrypter, Encrypter},
    DecryptRecord, Direction, EncryptInfo, EncryptRecord, MpcTlsChannel, MpcTlsLeaderConfig,
    TlsRole, Visibility,
};
use async_trait::async_trait;
use cipher::{aes::Aes128, Cipher};
use futures::SinkExt;
use hmac_sha256::{Prf, PrfOutput};
use ke::KeyExchange;
use key_exchange as ke;
use ludi::Context as LudiContext;
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Memory, MemoryExt, View, ViewExt,
};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use std::collections::VecDeque;
use tls_backend::{
    Backend, BackendError, BackendNotifier, BackendNotify, DecryptMode, EncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::Codec,
        enums::{AlertDescription, CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tracing::{debug, instrument, trace};

//mod actor;
//use actor::MpcTlsLeaderCtrl;

/// Controller for MPC-TLS leader.
//pub type LeaderCtrl = MpcTlsLeaderCtrl;

/// MPC-TLS leader.
pub struct MpcTlsLeader<K, P, C, Sc, Ctx, V> {
    config: MpcTlsLeaderConfig,
    role: TlsRole,
    channel: MpcTlsChannel,

    state: State,

    ke: K,
    prf: P,
    cipher: C,
    encrypter: Encrypter<Sc>,
    decrypter: Decrypter<Sc>,
    ctx: Ctx,
    vm: V,
    /// When set, notifies the backend that there are TLS messages which need to
    /// be decrypted.
    notifier: BackendNotifier,
    /// Whether the backend is ready to decrypt messages.
    is_decrypting: bool,
    /// Messages which have been committed but not yet decrypted.
    buffer: VecDeque<OpaqueMessage>,
    /// Whether we have already committed to the transcript.
    committed: bool,
    prf_out: Option<PrfOutput>,
}

impl<K, P, C, Sc, Ctx, V> MpcTlsLeader<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send + Flush<Ctx>,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    /// Create a new leader instance
    pub fn new(
        config: MpcTlsLeaderConfig,
        channel: MpcTlsChannel,
        ke: K,
        prf: P,
        cipher: C,
        encrypter: Encrypter<Sc>,
        decrypter: Decrypter<Sc>,
        ctx: Ctx,
        vm: V,
    ) -> Self {
        let is_decrypting = !config.defer_decryption_from_start();

        Self {
            config,
            role: TlsRole::Leader,
            channel,
            state: State::default(),
            ke,
            prf,
            cipher,
            encrypter,
            decrypter,
            ctx,
            vm,
            notifier: BackendNotifier::new(),
            is_decrypting,
            buffer: VecDeque::new(),
            committed: false,
            prf_out: None,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        // Allocate
        self.ke.alloc()?;
        self.encrypter.alloc()?;
        self.decrypter.alloc()?;

        // Setup
        let pms = self.ke.setup(vm)?.into_value();
        let prf_out = self.prf.setup(vm, pms)?;

        // Set up encryption
        self.cipher.set_key(prf_out.keys.client_write_key);
        self.cipher.set_iv(prf_out.keys.client_iv);

        let traffic_size = self.config.common().tx_config().max_online_size();
        let keystream_encrypt = self
            .cipher
            .alloc(vm, traffic_size)
            .map_err(MpcTlsError::cipher)?;

        let zero_ref: Array<U8, 16> = vm.alloc().map_err(MpcTlsError::vm)?;
        vm.mark_public(zero_ref).map_err(MpcTlsError::vm)?;

        let ghash_key = self
            .cipher
            .assign_block(vm, zero_ref, [0_u8; 16])
            .map_err(MpcTlsError::cipher)?;
        let ghash_key = transmute(ghash_key);
        let ghash_key = Decode::new(vm, self.role, ghash_key)?.shared(vm)?;

        self.encrypter.prepare(keystream_encrypt, ghash_key)?;

        // Set up decryption
        self.cipher.set_key(prf_out.keys.server_write_key);
        self.cipher.set_iv(prf_out.keys.server_iv);

        let traffic_size_mpc = self.config.common().rx_config().max_online_size();
        let traffic_size_zk = self.config.common().rx_config().max_offline_size();

        let keystream_decrypt_mpc = self
            .cipher
            .alloc(vm, traffic_size_mpc)
            .map_err(MpcTlsError::cipher)?;

        let keystream_decrypt_zk = self
            .cipher
            .alloc(vm, traffic_size_zk)
            .map_err(MpcTlsError::cipher)?;

        let zero_ref: Array<U8, 16> = vm.alloc().map_err(MpcTlsError::vm)?;
        vm.mark_public(zero_ref).map_err(MpcTlsError::vm)?;

        let ghash_key = self
            .cipher
            .assign_block(vm, zero_ref, [0_u8; 16])
            .map_err(MpcTlsError::cipher)?;
        let ghash_key = transmute(ghash_key);
        let ghash_key = Decode::new(vm, self.role, ghash_key)?.shared(vm)?;

        self.decrypter
            .prepare(keystream_decrypt_mpc, keystream_decrypt_zk, ghash_key)?;

        // Set client random
        let client_random = self.state.try_as_ke()?.client_random.0;
        self.prf.set_client_random(vm, Some(client_random))?;

        // Flush and preprocess
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.preprocess(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        self.prf
            .flush(ctx)
            .await
            .map_err(MpcTlsError::key_exchange)?;
        self.ke
            .flush(ctx)
            .await
            .map_err(MpcTlsError::key_exchange)?;

        Ok(())
    }

    fn check_transcript_length(&self, direction: Direction, len: usize) -> Result<(), MpcTlsError> {
        match direction {
            Direction::Sent => {
                let new_len = self.encrypter.sent_bytes() + len;
                let max_size = self.config.common().tx_config().max_online_size();
                if new_len > max_size {
                    return Err(MpcTlsError::config(format!(
                        "max sent transcript size exceeded: {} > {}",
                        new_len, max_size
                    )));
                }
            }
            Direction::Recv => {
                let new_len = self.decrypter.recv_bytes() + len;
                let max_size = self.config.common().rx_config().max_online_size()
                    + self.config.common().rx_config().max_offline_size();
                if new_len > max_size {
                    return Err(MpcTlsError::config(format!(
                        "max received transcript size exceeded: {} > {}",
                        new_len, max_size
                    )));
                }
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_client_finished(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        let Cf { data } = self.state.take().try_into_cf()?;
        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::EncryptClientFinished(EncryptClientFinished))
            .await?;

        let msg = EncryptRecord {
            info: EncryptInfo::Message(msg),
            visibility: Visibility::Public,
        };

        let msg = self.encrypter.encrypt(vm, ctx, msg).await?;

        self.state = State::Sf(Sf { data });

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_alert(&mut self, msg: PlainMessage) -> Result<OpaqueMessage, MpcTlsError> {
        if let Some(alert) = AlertMessagePayload::read_bytes(&msg.payload.0) {
            // We only allow CloseNotify alerts.
            if alert.description != AlertDescription::CloseNotify {
                return Err(MpcTlsError::other(
                    "attempted to send an alert other than CloseNotify",
                ));
            }
        } else {
            return Err(MpcTlsError::other(
                "attempted to send an alert other than CloseNotify",
            ));
        }

        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::EncryptAlert(EncryptAlert {
                msg: msg.payload.0.clone(),
            }))
            .await?;

        let msg = EncryptRecord {
            info: EncryptInfo::Message(msg),
            visibility: Visibility::Public,
        };
        let msg = self.encrypter.encrypt(vm, ctx, msg).await?;

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_application_data(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        self.state.try_as_active()?;
        self.check_transcript_length(Direction::Sent, msg.payload.0.len())?;

        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::EncryptMessage(EncryptMessage {
                len: msg.payload.0.len(),
            }))
            .await?;

        let msg = EncryptRecord {
            info: EncryptInfo::Message(msg),
            visibility: Visibility::Private,
        };
        let msg = self.encrypter.encrypt(vm, ctx, msg).await?;

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_server_finished(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        let Sf { data } = self.state.take().try_into_sf()?;
        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::DecryptServerFinished(
                DecryptServerFinished {
                    ciphertext: msg.payload.0.clone(),
                },
            ))
            .await?;

        let msg = DecryptRecord {
            msg,
            visibility: Visibility::Public,
        };

        let msg = self.decrypter.decrypt_public(vm, ctx, vec![msg]).await?;
        let msg = msg
            .expect("Leader should recieve some message")
            .pop()
            .expect("Should contain a message");

        self.state = State::Active(Active { data });

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_alert(&mut self, msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
        self.state.try_as_active()?;
        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::DecryptAlert(DecryptAlert {
                ciphertext: msg.payload.0.clone(),
            }))
            .await?;

        let msg = DecryptRecord {
            msg,
            visibility: Visibility::Public,
        };

        let msg = self.decrypter.decrypt_public(vm, ctx, vec![msg]).await?;
        let msg = msg
            .expect("Leader should recieve some message")
            .pop()
            .expect("Should contain a message");

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_application_data(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        self.state.try_as_active()?;
        self.check_transcript_length(Direction::Recv, msg.payload.0.len())?;

        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        self.channel
            .send(MpcTlsMessage::DecryptMessage(DecryptMessage))
            .await?;

        let msg = DecryptRecord {
            msg,
            visibility: Visibility::Private,
        };

        let msg = self.decrypter.decrypt_private(vm, ctx, vec![msg]).await?;
        let msg = msg
            .expect("Leader should recieve some message")
            .pop()
            .expect("Should contain a message");

        Ok(msg)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn commit(&mut self) -> Result<(), MpcTlsError> {
        if self.committed {
            return Ok(());
        }
        self.state.try_as_active()?;

        debug!("committing to transcript");

        self.channel.send(MpcTlsMessage::Commit(Commit)).await?;

        self.committed = true;

        if !self.buffer.is_empty() {
            self.buffer.make_contiguous();
            self.decrypter
                .verify_tags(&mut self.vm, &mut self.ctx, self.buffer.as_slices().0)
                .await?;
            self.decode_key().await?;
            self.is_decrypting = true;
            self.notifier.set();
        }

        Ok(())
    }

    /// Closes the connection.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    pub async fn close_connection(
        &mut self,
        ctx: &mut LudiContext<Self>,
    ) -> Result<(), MpcTlsError> {
        debug!("closing connection");

        self.channel
            .send(MpcTlsMessage::CloseConnection(CloseConnection))
            .await?;

        let Active { data } = self.state.take().try_into_active()?;

        self.state = State::Closed(Closed { data });

        ctx.stop();

        Ok(())
    }

    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&mut self) -> Result<(), MpcTlsError> {
        if self.committed {
            return Ok(());
        }

        self.is_decrypting = false;
        self.notifier.clear();

        Ok(())
    }

    pub async fn decode_key(&mut self) -> Result<(), MpcTlsError> {
        let vm = &mut self.vm;
        let ctx = &mut self.ctx;

        let key = self.cipher.key().map_err(MpcTlsError::cipher)?;
        let key = transmute(key);
        let key = Decode::new(vm, self.role, key)?.private(vm)?;

        let iv = self.cipher.iv().map_err(MpcTlsError::cipher)?;
        let iv = transmute(iv);
        let iv = Decode::new(vm, self.role, iv)?.private(vm)?;

        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        let (key, iv) = futures::try_join!(key.decode(), iv.decode())?;
        self.decrypter.set_key_and_iv(key, iv);

        Ok(())
    }
}

#[async_trait]
impl<K, P, C, Sc, Ctx, V> Backend for MpcTlsLeader<K, P, C, Sc, Ctx, V>
where
    Self: Send,
    K: KeyExchange<V> + Send + Flush<Ctx>,
    P: Prf<V> + Send + Flush<Ctx>,
    C: Cipher<Aes128, V> + Send,
    Ctx: Context + Send,
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
    Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
    Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
    Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
{
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        let Ke {
            protocol_version, ..
        } = self.state.try_as_ke_mut()?;

        trace!("setting protocol version: {:?}", version);

        *protocol_version = Some(version);

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let Ke { cipher_suite, .. } = self.state.try_as_ke_mut()?;

        trace!("setting cipher suite: {:?}", suite);

        *cipher_suite = Some(suite.suite());

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        unimplemented!()
    }

    async fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        let Ke { client_random, .. } = self.state.try_as_ke()?;

        Ok(*client_random)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        let pk = self
            .ke
            .client_key()
            .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        let Ke { server_random, .. } = self.state.try_as_ke_mut()?;

        *server_random = Some(random);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        let Ke {
            ref mut server_public_key,
            ..
        } = self.state.try_as_ke_mut()?;

        if key.group != NamedGroup::secp256r1 {
            Err(BackendError::InvalidServerKey(format!(
                "unsupported key group: {:?}",
                key.group
            )))
        } else {
            let server_key = p256::PublicKey::from_sec1_bytes(&key.key)
                .map_err(|err| BackendError::InvalidServerKey(err.to_string()))?;

            *server_public_key = Some(key);

            self.ke
                .set_server_key(server_key)
                .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

            Ok(())
        }
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        let Ke {
            ref mut server_cert_details,
            ..
        } = self.state.try_as_ke_mut()?;

        *server_cert_details = Some(cert_details);

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        let Ke {
            ref mut server_kx_details,
            ..
        } = self.state.try_as_ke_mut()?;

        *server_kx_details = Some(kx_details);

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(
        &mut self,
        _hash: Vec<u8>,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: Vec<u8>) -> Result<(), BackendError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            BackendError::ServerFinished(
                "server finished handshake hash is not 32 bytes".to_string(),
            )
        })?;

        self.channel
            .send(MpcTlsMessage::ServerFinishedVd(ServerFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        self.prf
            .set_sf_hash(&mut self.vm, hash)
            .map_err(|err| BackendError::ServerFinished(err.to_string()))?;

        let sf_vd = self.prf_out.expect("Prf output should be set").sf_vd;

        let ctx = &mut self.ctx;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .execute(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let sf_vd = self
            .vm
            .decode(sf_vd)
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?
            .await
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?;

        Ok(sf_vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            BackendError::ClientFinished(
                "client finished handshake hash is not 32 bytes".to_string(),
            )
        })?;

        self.channel
            .send(MpcTlsMessage::ClientFinishedVd(ClientFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?;

        self.prf
            .set_cf_hash(&mut self.vm, hash)
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?;

        let cf_vd = self.prf_out.expect("Prf output should be set").cf_vd;

        let ctx = &mut self.ctx;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .execute(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let cf_vd = self
            .vm
            .decode(cf_vd)
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?
            .await
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?;

        Ok(cf_vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        let Ke {
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_public_key,
            server_kx_details,
        } = self.state.take().try_into_ke()?;

        let protocol_version =
            protocol_version.ok_or(BackendError::Other("protocol version not set".to_string()))?;
        let cipher_suite =
            cipher_suite.ok_or(BackendError::Other("cipher suite not set".to_string()))?;
        let server_cert_details =
            server_cert_details.ok_or(BackendError::Other("server cert not set".to_string()))?;
        let server_kx_details = server_kx_details
            .ok_or(BackendError::Other("server kx details not set".to_string()))?;
        let server_public_key = server_public_key
            .ok_or(BackendError::Other("server public key not set".to_string()))?;
        let server_random =
            server_random.ok_or(BackendError::Other("server random not set".to_string()))?;

        let handshake_data = HandshakeData::new(
            server_cert_details.clone(),
            server_kx_details.clone(),
            client_random,
            server_random,
        );

        self.channel
            .send(MpcTlsMessage::ComputeKeyExchange(ComputeKeyExchange {
                server_random: server_random.0,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let eq = self
            .ke
            .compute_pms(&mut self.vm)
            .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

        self.prf
            .set_server_random(&mut self.vm, server_random.0)
            .map_err(|err| BackendError::Prf(err.to_string()))?;

        let ctx = &mut self.ctx;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .execute(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        self.vm
            .flush(ctx)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        eq.check()
            .await
            .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

        // Set ghash keys
        // TODO: Optimize this with ctx try join
        self.encrypter
            .start(ctx)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?;
        self.decrypter
            .start(ctx)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?;

        self.state = State::Cf(Cf {
            data: MpcTlsData {
                protocol_version,
                cipher_suite,
                client_random,
                server_random,
                server_cert_details,
                server_public_key,
                server_kx_details,
                handshake_data,
            },
        });

        Ok(())
    }

    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        _seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self
                .encrypt_client_finished(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            ContentType::ApplicationData => self
                .encrypt_application_data(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            ContentType::Alert => self
                .encrypt_alert(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            _ => {
                return Err(BackendError::EncryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        };

        Ok(msg)
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        _seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self
                .decrypt_server_finished(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            ContentType::ApplicationData => self
                .decrypt_application_data(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            ContentType::Alert => self
                .decrypt_alert(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            _ => {
                return Err(BackendError::DecryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        };

        Ok(msg)
    }

    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        if self.committed {
            return Err(BackendError::InternalError(
                "cannot buffer messages after committing to transcript".to_string(),
            ));
        }

        if msg.typ == ContentType::ApplicationData {
            self.channel
                .send(MpcTlsMessage::CommitMessage(CommitMessage {
                    msg: msg.payload.0.clone(),
                }))
                .await
                .map_err(|e| BackendError::InternalError(e.to_string()))?;
        }

        self.buffer.push_back(msg);

        if self.is_decrypting {
            self.notifier.set();
        }

        Ok(())
    }

    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        if !self.is_decrypting && self.state.is_active() {
            return Ok(None);
        }

        if self.buffer.is_empty() {
            self.notifier.clear();
        }

        Ok(self.buffer.pop_front())
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(self.notifier.get())
    }

    async fn buffer_len(&mut self) -> Result<usize, BackendError> {
        Ok(self.buffer.len())
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.commit()
            .await
            .map_err(|err| BackendError::Other(err.to_string()))
    }
}

/// Data collected by the MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsData {
    /// TLS protocol version.
    pub protocol_version: ProtocolVersion,
    /// TLS cipher suite.
    pub cipher_suite: CipherSuite,
    /// Client random.
    pub client_random: Random,
    /// Server random.
    pub server_random: Random,
    /// Server certificate details.
    pub server_cert_details: ServerCertDetails,
    /// Server ephemeral public key.
    pub server_public_key: PublicKey,
    /// Server key exchange details, eg signature.
    pub server_kx_details: ServerKxDetails,
    /// Handshake data.
    pub handshake_data: HandshakeData,
}

pub(crate) mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(crate) enum State {
        Ke(Ke),
        Cf(Cf),
        Sf(Sf),
        Active(Active),
        Closed(Closed),
        Error,
    }

    impl State {
        pub(super) fn take(&mut self) -> Self {
            std::mem::replace(self, State::Error)
        }
    }

    impl Default for State {
        fn default() -> Self {
            State::Ke(Ke {
                protocol_version: None,
                cipher_suite: None,
                client_random: Random::new().expect("rng is available"),
                server_random: None,
                server_cert_details: None,
                server_public_key: None,
                server_kx_details: None,
            })
        }
    }

    impl From<StateError> for BackendError {
        fn from(err: StateError) -> Self {
            BackendError::InvalidState(err.to_string())
        }
    }

    #[derive(Debug)]
    pub(crate) struct Ke {
        pub(crate) protocol_version: Option<ProtocolVersion>,
        pub(crate) cipher_suite: Option<CipherSuite>,
        pub(crate) client_random: Random,
        pub(crate) server_random: Option<Random>,
        pub(crate) server_cert_details: Option<ServerCertDetails>,
        pub(crate) server_public_key: Option<PublicKey>,
        pub(crate) server_kx_details: Option<ServerKxDetails>,
    }

    #[derive(Debug)]
    pub(crate) struct Cf {
        pub(crate) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(crate) struct Sf {
        pub(crate) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(crate) struct Active {
        pub(crate) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(crate) struct Closed {
        pub(crate) data: MpcTlsData,
    }
}

use state::*;

use crate::{
    decode::Decode,
    msg::MpcTlsMessage,
    record_layer::{aead::transmute, Decrypter, Encrypter},
    DecryptRecord, Direction, EncryptInfo, EncryptRecord, MpcTlsChannel, MpcTlsError,
    MpcTlsFollowerConfig, TlsRole, Visibility,
};
use cipher::{aes::Aes128, Cipher};
use futures::{
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use hmac_sha256::{Prf, PrfOutput};
use ke::KeyExchange;
use key_exchange as ke;
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Memory, MemoryExt, View, ViewExt,
};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::{collections::VecDeque, mem};
use tls_core::{
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        codec::Codec,
        enums::{AlertDescription, ContentType, HandshakeType, NamedGroup, ProtocolVersion},
        handshake::{HandshakeMessagePayload, HandshakePayload},
        message::{OpaqueMessage, PlainMessage},
    },
};
use tracing::{debug, instrument};

// mod actor;
// use actor::MpcTlsFollowerCtrl;

/// Controller for MPC-TLS follower.
// pub type FollowerCtrl = MpcTlsFollowerCtrl;

/// MPC-TLS follower.
pub struct MpcTlsFollower<K, P, C, Sc, Ctx, V> {
    state: State,
    config: MpcTlsFollowerConfig,
    role: TlsRole,

    _sink: SplitSink<MpcTlsChannel, MpcTlsMessage>,
    stream: Option<SplitStream<MpcTlsChannel>>,

    ke: K,
    prf: P,
    cipher: C,
    encrypter: Encrypter<Sc>,
    decrypter: Decrypter<Sc>,
    ctx: Ctx,
    vm: V,
    prf_output: Option<PrfOutput>,

    /// Whether the server has sent a CloseNotify alert.
    close_notify: bool,
    /// Whether the leader has committed to the transcript.
    committed: bool,
}

impl<K, P, C, Sc, Ctx, V> MpcTlsFollower<K, P, C, Sc, Ctx, V>
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
    /// Creates a new follower.
    pub fn new(
        config: MpcTlsFollowerConfig,
        channel: MpcTlsChannel,
        ke: K,
        prf: P,
        cipher: C,
        encrypter: Encrypter<Sc>,
        decrypter: Decrypter<Sc>,
        ctx: Ctx,
        vm: V,
    ) -> Self {
        let (_sink, stream) = channel.split();

        Self {
            state: State::Init,
            config,
            role: TlsRole::Follower,
            _sink,
            stream: Some(stream),
            ke,
            prf,
            cipher,
            encrypter,
            decrypter,
            ctx,
            vm,
            prf_output: None,
            close_notify: false,
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "trace", skip_all, err)]
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
        self.prf_output = Some(prf_out);

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
        self.prf.set_client_random(vm, None)?;

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

    /// Returns an error if the follower is not accepting new messages.
    ///
    /// This can happen if the follower has received a CloseNotify alert or if
    /// the leader has committed to the transcript.
    fn is_accepting_messages(&self) -> Result<(), MpcTlsError> {
        if self.close_notify {
            return Err(MpcTlsError::peer(
                "attempted to commit a message after receiving CloseNotify",
            ));
        }

        if self.committed {
            return Err(MpcTlsError::peer(
                "attempted to commit a new message after committing transcript",
            ));
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn compute_key_exchange(&mut self, server_random: [u8; 32]) -> Result<(), MpcTlsError> {
        self.state.take().try_into_init()?;

        // Key exchange
        let eq = self.ke.compute_pms(&mut self.vm)?;

        let server_key = self
            .ke
            .server_key()
            .expect("server key should be set after computing pms");

        // PRF
        let ctx = &mut self.ctx;
        let vm = &mut self.vm;
        self.prf.set_server_random(vm, server_random)?;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        eq.check().await.map_err(MpcTlsError::key_exchange)?;

        // Encryption and decryption preparation.
        self.encrypter
            .start(ctx)
            .await
            .map_err(MpcTlsError::encrypt)?;
        self.decrypter
            .start(ctx)
            .await
            .map_err(MpcTlsError::decrypt)?;

        self.state = State::Ke(Ke {
            server_key: PublicKey::new(
                NamedGroup::secp256r1,
                server_key.to_encoded_point(false).as_bytes(),
            ),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn client_finished_vd(&mut self, handshake_hash: [u8; 32]) -> Result<(), MpcTlsError> {
        let Ke { server_key } = self.state.take().try_into_ke()?;

        self.prf.set_cf_hash(&mut self.vm, handshake_hash)?;
        let prf_output = self.prf_output.expect("Prf output should be some");
        let client_finished = prf_output.cf_vd;
        let client_finished = self.vm.decode(client_finished).map_err(MpcTlsError::vm)?;

        let ctx = &mut self.ctx;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        let client_finished = client_finished.await?;

        self.state = State::Cf(Cf {
            server_key,
            client_finished,
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn server_finished_vd(&mut self, handshake_hash: [u8; 32]) -> Result<(), MpcTlsError> {
        let Sf {
            server_key,
            server_finished,
        } = self.state.take().try_into_sf()?;

        self.prf.set_sf_hash(&mut self.vm, handshake_hash)?;
        let prf_output = self.prf_output.expect("Prf output should be some");
        let expected_server_finished = prf_output.sf_vd;
        let expected_server_finished = self
            .vm
            .decode(expected_server_finished)
            .map_err(MpcTlsError::vm)?;

        let ctx = &mut self.ctx;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        self.vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        let expected_server_finished = expected_server_finished.await?;

        let Some(server_finished) = server_finished else {
            return Err(MpcTlsError::prf("server finished is not set"));
        };

        if server_finished != expected_server_finished {
            return Err(MpcTlsError::prf("server finished does not match"));
        }

        self.state = State::Active(Active {
            server_key,
            buffer: Default::default(),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_client_finished(&mut self) -> Result<(), MpcTlsError> {
        let Cf {
            server_key,
            client_finished,
        } = self.state.take().try_into_cf()?;

        let msg = HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(client_finished)),
        };
        let mut payload = Vec::new();
        msg.encode(&mut payload);

        let encrypt = EncryptRecord {
            info: EncryptInfo::Message(PlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload(payload),
            }),
            visibility: Visibility::Public,
        };

        self.encrypter
            .encrypt(&mut self.vm, &mut self.ctx, encrypt)
            .await?;

        self.state = State::Sf(Sf {
            server_key,
            server_finished: None,
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        if let Some(alert) = AlertMessagePayload::read_bytes(&msg) {
            // We only allow the leader to send a CloseNotify alert
            if alert.description != AlertDescription::CloseNotify {
                return Err(MpcTlsError::peer(
                    "attempted to send an alert other than CloseNotify",
                ));
            }
        } else {
            return Err(MpcTlsError::peer("invalid alert message"));
        }

        let encrypt = EncryptRecord {
            info: EncryptInfo::Message(PlainMessage {
                typ: ContentType::Alert,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            }),
            visibility: Visibility::Public,
        };

        self.encrypter
            .encrypt(&mut self.vm, &mut self.ctx, encrypt)
            .await?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_message(&mut self, len: usize) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        self.check_transcript_length(Direction::Sent, len)?;
        self.state.try_as_active()?;

        let encrypt = EncryptRecord {
            info: EncryptInfo::Length(len),
            visibility: Visibility::Private,
        };

        self.encrypter
            .encrypt(&mut self.vm, &mut self.ctx, encrypt)
            .await?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn commit_message(&mut self, payload: Vec<u8>) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        self.check_transcript_length(Direction::Recv, payload.len())?;
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        buffer.push_back(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_server_finished(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        let Sf {
            server_finished, ..
        } = self.state.try_as_sf_mut()?;

        let decrypt = DecryptRecord {
            msg: OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            },
            visibility: Visibility::Public,
        };

        let msg = self
            .decrypter
            .decrypt_public(&mut self.vm, &mut self.ctx, vec![decrypt])
            .await?;

        let msg = msg
            .expect("Follower should get some public message decrypted")
            .pop()
            .expect("Should be some message available");

        let msg = msg.payload.0;
        if msg.len() != 16 {
            return Err(MpcTlsError::decrypt(
                "server finished message is not 16 bytes",
            ));
        }

        let sf: [u8; 12] = msg[4..].try_into().expect("slice should be 12 bytes");

        server_finished.replace(sf);

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.state.try_as_active()?;

        let decrypt = DecryptRecord {
            msg: OpaqueMessage {
                typ: ContentType::Alert,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            },
            visibility: Visibility::Public,
        };
        let msg = self
            .decrypter
            .decrypt_public(&mut self.vm, &mut self.ctx, vec![decrypt])
            .await?;

        let alert = msg
            .expect("Follower should get some public message decrypted")
            .pop()
            .expect("Should be some message available");

        let Some(alert) = AlertMessagePayload::read_bytes(&alert.payload.0) else {
            return Err(MpcTlsError::other("server sent an invalid alert"));
        };

        if alert.description != AlertDescription::CloseNotify {
            return Err(MpcTlsError::peer("server sent a fatal alert"));
        }

        self.close_notify = true;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_message(&mut self) -> Result<(), MpcTlsError> {
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        let msg = buffer.pop_front().ok_or(MpcTlsError::peer(
            "attempted to decrypt message when no messages are committed",
        ))?;

        debug!("decrypting message");

        let decrypt = DecryptRecord {
            msg,
            visibility: Visibility::Private,
        };
        self.decrypter
            .decrypt_private(&mut self.vm, &mut self.ctx, vec![decrypt])
            .await?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        let Active { server_key, buffer } = self.state.take().try_into_active()?;

        if !buffer.is_empty() {
            return Err(MpcTlsError::peer(
                "attempted to close connection without decrypting all messages",
            ));
        }

        self.state = State::Closed(Closed { server_key });

        Ok(())
    }

    async fn commit(&mut self) -> Result<(), MpcTlsError> {
        let Active { ref mut buffer, .. } = self.state.try_as_active_mut()?;

        debug!("leader committed transcript");

        self.committed = true;

        // Reveal the AEAD key to the leader only if there are TLS messages which need
        // to be decrypted.
        if !buffer.is_empty() {
            buffer.make_contiguous();
            self.decrypter
                .verify_tags(&mut self.vm, &mut self.ctx, buffer.as_slices().0)
                .await?;
            self.decode_key().await?;
        }

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

/// Data collected by the MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollowerData {
    /// The server's public key
    pub server_key: PublicKey,
    /// The total number of bytes sent
    pub bytes_sent: usize,
    /// The total number of bytes received
    pub bytes_recv: usize,
}

mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(super) enum State {
        Init,
        Ke(Ke),
        Cf(Cf),
        Sf(Sf),
        Active(Active),
        Closed(Closed),
        Error,
    }

    impl State {
        pub(super) fn take(&mut self) -> Self {
            mem::replace(self, State::Error)
        }
    }

    impl From<StateError> for MpcTlsError {
        fn from(err: StateError) -> Self {
            MpcTlsError::state(err)
        }
    }

    #[derive(Debug)]
    pub(super) struct Ke {
        pub(super) server_key: PublicKey,
    }

    #[derive(Debug)]
    pub(super) struct Cf {
        pub(super) server_key: PublicKey,
        pub(super) client_finished: [u8; 12],
    }

    #[derive(Debug)]
    pub(super) struct Sf {
        pub(super) server_key: PublicKey,
        pub(super) server_finished: Option<[u8; 12]>,
    }

    #[derive(Debug)]
    pub(super) struct Active {
        pub(super) server_key: PublicKey,
        /// TLS messages purportedly received by the leader from the server.
        ///
        /// The follower must verify the authenticity of these messages with
        /// AEAD verification (i.e. by verifying the authentication
        /// tag).
        pub(super) buffer: VecDeque<OpaqueMessage>,
    }

    #[derive(Debug)]
    pub(super) struct Closed {
        pub(super) server_key: PublicKey,
    }
}

use state::*;

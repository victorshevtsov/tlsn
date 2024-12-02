//! Record layer decryption.

use crate::{
    decode::OneTimePadShared,
    record_layer::{
        aead::{
            decrypt::AesGcmDecrypt,
            ghash::{Ghash, Tag},
        },
        Visibility,
    },
    transcript::Transcript,
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{binary::Binary, View};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        enums::{ContentType, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    },
};

/// Handles decryption operations.
///
/// Deals with necessary setup and preparation in [`DecryptState`]. References to decryption input
/// i.e. ciphertext is written to [`Transcript`]. Prepares decryption for batched processing by
/// building [`DecryptRequest`]s and delegating actual decryption to [`AesGcmDecrypt`].
pub struct Decrypter<Sc> {
    role: TlsRole,
    decrypt_local: bool,
    transcript: Transcript,
    state: DecryptState<Sc>,
}

impl<Sc> Decrypter<Sc> {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `role` - The role, either leader or follower.
    /// * `ghash` - The instance for computing ghash.
    pub(crate) fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
            decrypt_local: false,
            transcript: Transcript::default(),
            state: DecryptState::Init { ghash },
        }
    }

    /// Allocates resources needed for decryption.
    pub(crate) fn alloc(&mut self) -> Result<(), MpcTlsError>
    where
        Sc: ShareConvert<Gf2_128>,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    {
        let DecryptState::Init { ref mut ghash } = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Init state"));
        };

        ghash.alloc()?;
        Ok(())
    }

    /// Returns the number of received bytes.
    pub(crate) fn recv_bytes(&self) -> usize {
        self.transcript.size()
    }

    /// Injects further dependencies needed for decryption.
    ///
    /// # Arguments
    ///
    /// * `keystream_mpc` - Provides keystream operations for MPC.
    /// * `keystream_zk` - Provides keystream operations for ZK.
    /// * `ghash_key` - The ghash key.
    pub(crate) fn prepare(
        &mut self,
        keystream_mpc: Keystream<Aes128>,
        keystream_zk: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    ) -> Result<(), MpcTlsError> {
        let DecryptState::Init { ghash, .. } =
            std::mem::replace(&mut self.state, DecryptState::Error)
        else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Init state"));
        };

        self.state = DecryptState::Prepared {
            ghash,
            keystream_mpc,
            keystream_zk,
            ghash_key,
        };
        Ok(())
    }

    /// Sets decryption key and iv.
    ///
    /// # Arguments
    ///
    /// * `key` - The key, if available.
    /// * `iv` - The iv, if available.
    pub(crate) fn set_key_and_iv(
        &mut self,
        key: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
    ) -> Result<(), MpcTlsError> {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };

        aes.set_key_and_iv(key, iv);
        self.decrypt_local = true;
        Ok(())
    }

    /// Finishes setup for decryption.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    pub(crate) async fn start<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), MpcTlsError>
    where
        Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
        Ctx: Context,
    {
        let DecryptState::Prepared {
            mut ghash,
            keystream_mpc,
            keystream_zk,
            ghash_key,
        } = std::mem::replace(&mut self.state, DecryptState::Error)
        else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Prepared state"));
        };

        let key = ghash_key.decode().await?;

        ghash.set_key(key)?;
        ghash.flush(ctx).await?;
        let ghash = ghash.finalize()?;

        let aes = AesGcmDecrypt::new(self.role, keystream_mpc, keystream_zk, ghash);
        self.state = DecryptState::Ready(aes);

        Ok(())
    }

    /// Verifies tags.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The context for IO.
    /// * `messages` - The messages to verify.
    pub(crate) async fn verify_tags<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        messages: &[OpaqueMessage],
    ) -> Result<(), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };
        let mut decrypts = Vec::with_capacity(messages.len());

        let mut seq = self.transcript.seq();
        for msg in messages.iter().cloned() {
            let visibility = match msg.typ {
                ContentType::ApplicationData => Visibility::Private,
                _ => Visibility::Public,
            };
            let message = DecryptRecord { msg, visibility };
            let decrypt = Self::prepare_tag_verify(seq, message)?;

            seq += 1;
            decrypts.push(decrypt);
        }

        aes.verify_tags(vm, ctx, decrypts).await?;
        Ok(())
    }

    /// Decrypts messages publicly.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The context for IO.
    /// * `messages` - The messages to decrypt.
    pub(crate) async fn decrypt_public<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        messages: Vec<DecryptRecord>,
    ) -> Result<Option<Vec<PlainMessage>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };

        let mut decrypts = Vec::with_capacity(messages.len());
        let mut typs = Vec::with_capacity(messages.len());

        for message in messages {
            let seq = self.transcript.inc_seq();
            let (decrypt, typ) = Self::prepare_decrypt(seq, message)?;

            decrypts.push(decrypt);
            typs.push(typ);
        }

        let (messages, plaintext_refs) = aes.decrypt(vm, ctx, decrypts).await?;

        for (&typ, plaintext_ref) in typs.iter().zip(plaintext_refs) {
            self.transcript.record(typ, plaintext_ref);
        }

        Ok(messages)
    }

    /// Decrypts messages privately for the leader.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The context for IO.
    /// * `messages` - The messages to decrypt.
    pub(crate) async fn decrypt_private<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        messages: Vec<DecryptRecord>,
    ) -> Result<Option<Vec<PlainMessage>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };

        let mut decrypts = Vec::with_capacity(messages.len());
        let mut explicit_nonces = Vec::with_capacity(messages.len());
        let mut purported_ciphertexts = Vec::with_capacity(messages.len());
        let mut typs = Vec::with_capacity(messages.len());

        for message in messages {
            let seq = self.transcript.inc_seq();
            let (decrypt, typ) = Self::prepare_decrypt(seq, message)?;

            explicit_nonces.push(decrypt.explicit_nonce);
            purported_ciphertexts.push(decrypt.ciphertext.clone());
            decrypts.push(decrypt);
            typs.push(typ);
        }

        let (messages, plaintext_refs) = if self.decrypt_local {
            aes.decrypt_local(vm, decrypts).await?
        } else {
            aes.decrypt(vm, ctx, decrypts).await?
        };

        for (&typ, plaintext_ref) in typs.iter().zip(plaintext_refs.iter().copied()) {
            self.transcript.record(typ, plaintext_ref);
        }

        // TODO: Use zk vm here:
        let ciphertexts = aes
            .prove(vm, ctx, messages.clone(), plaintext_refs, explicit_nonces)
            .await?;

        if ciphertexts != purported_ciphertexts {
            return Err(MpcTlsError::other(
                "Ciphertexts do not re-encrypt back correctly",
            ));
        }

        Ok(messages)
    }

    /// Prepares data for tag verification.
    ///
    /// # Arguments
    ///
    /// * `seq` - TLS sequence number.
    /// * `message` - The message for tag verification.
    fn prepare_tag_verify(seq: u64, message: DecryptRecord) -> Result<DecryptRequest, MpcTlsError> {
        let DecryptRecord { msg, visibility } = message;

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;

        let mut ciphertext = payload.0;

        let explicit_nonce: [u8; 8] = ciphertext
            .drain(..8)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Should be able to drain explicit nonce");

        let purported_tag = Tag::new(ciphertext.split_off(ciphertext.len() - 16));
        let len = ciphertext.len();
        let aad = make_tls12_aad(seq, typ, version, len);

        let decrypt = DecryptRequest {
            ciphertext,
            typ,
            visibility,
            version,
            explicit_nonce,
            aad,
            purported_tag,
        };

        Ok(decrypt)
    }

    /// Prepares data for decryption.
    ///
    /// # Arguments
    ///
    /// * `seq` - TLS sequence number.
    /// * `message` - The message to decrypt.
    fn prepare_decrypt(
        seq: u64,
        message: DecryptRecord,
    ) -> Result<(DecryptRequest, ContentType), MpcTlsError> {
        let DecryptRecord { msg, visibility } = message;

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;

        let mut ciphertext = payload.0;

        let explicit_nonce: [u8; 8] = ciphertext
            .drain(..8)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Should be able to drain explicit nonce");
        let purported_tag = Tag::new(ciphertext.split_off(ciphertext.len() - 16));
        let len = ciphertext.len();
        let aad = make_tls12_aad(seq, typ, version, len);

        let decrypt = DecryptRequest {
            ciphertext,
            typ,
            visibility,
            version,
            explicit_nonce,
            aad,
            purported_tag,
        };
        Ok((decrypt, typ))
    }
}

/// Wrapper for TLS records that need to be decrypted.
pub(crate) struct DecryptRecord {
    pub(crate) msg: OpaqueMessage,
    pub(crate) visibility: Visibility,
}

/// Contains data for decryption.
pub(crate) struct DecryptRequest {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) typ: ContentType,
    pub(crate) visibility: Visibility,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: [u8; 8],
    pub(crate) aad: [u8; 13],
    pub(crate) purported_tag: Tag,
}

/// Inner state of [`Decrypter`].
enum DecryptState<Sc> {
    Init {
        ghash: Ghash<Sc>,
    },
    Prepared {
        ghash: Ghash<Sc>,
        keystream_mpc: Keystream<Aes128>,
        keystream_zk: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    },
    Ready(AesGcmDecrypt),
    Error,
}

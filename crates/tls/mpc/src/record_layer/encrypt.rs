//! Record layer encryption.

use crate::{
    decode::OneTimePadShared,
    record_layer::{
        aead::{encrypt::AesGcmEncrypt, ghash::Ghash},
        Visibility,
    },
    transcript::Transcript,
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Vector, View, ViewExt,
};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{Execute, Vm};
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        enums::{ContentType, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    },
};

/// Handles encryption operations.
///
/// Deals with necessary setup and preparation in [`EncryptState`]. References to encryption input
/// i.e. plaintext is written to [`Transcript`]. Prepares encryption for batched processing by
/// building [`EncryptRequest`]s and delegating actual encryption to [`AesGcmEncrypt`].
pub struct Encrypter<Sc> {
    role: TlsRole,
    transcript: Transcript,
    state: EncryptState<Sc>,
}

impl<Sc> Encrypter<Sc> {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `role` - The role, either leader or follower.
    /// * `ghash` - The instance for computing ghash.
    pub(crate) fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
            transcript: Transcript::default(),
            state: EncryptState::Init { ghash },
        }
    }

    /// Allocates resources needed for encryption.
    pub(crate) fn alloc(&mut self) -> Result<(), MpcTlsError>
    where
        Sc: ShareConvert<Gf2_128>,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
    {
        let EncryptState::Init { ref mut ghash, .. } = self.state else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Init state"));
        };

        ghash.alloc()?;
        Ok(())
    }

    /// Injects further dependencies needed for encryption.
    ///
    /// # Arguments
    ///
    /// * `keystream` - Provides keystream operations.
    /// * `ghash_key` - The ghash key.
    pub(crate) fn prepare(
        &mut self,
        keystream: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    ) -> Result<(), MpcTlsError> {
        let EncryptState::Init { ghash } = std::mem::replace(&mut self.state, EncryptState::Error)
        else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Init state"));
        };

        self.state = EncryptState::Prepared {
            ghash,
            keystream,
            ghash_key,
        };
        Ok(())
    }

    /// Returns the number of sent bytes.
    pub(crate) fn sent_bytes(&self) -> usize {
        self.transcript.size()
    }

    /// Finishes setup for encryption.
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
        let EncryptState::Prepared {
            mut ghash,
            keystream,
            ghash_key,
        } = std::mem::replace(&mut self.state, EncryptState::Error)
        else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Prepared state"));
        };

        let key = ghash_key.decode().await?;

        ghash.set_key(key)?;
        ghash.flush(ctx).await?;
        let ghash = ghash.finalize()?;

        let aes = AesGcmEncrypt::new(self.role, keystream, ghash);
        self.state = EncryptState::Ready(aes);

        Ok(())
    }

    /// Encrypts a message.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The context for IO.
    /// * `message` - The message to encrypt.
    pub(crate) async fn encrypt<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        message: EncryptRecord,
    ) -> Result<OpaqueMessage, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let EncryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Ready state"));
        };

        let seq = self.transcript.inc_seq();
        let encrypt = Self::prepare_encrypt(self.role, vm, seq, message)?;

        let typ = encrypt.typ;
        let plaintext_ref = encrypt.plaintext_ref;

        self.transcript.record(typ, plaintext_ref);

        let mut message = aes.encrypt(vm, ctx, vec![encrypt]).await?;
        let message = message
            .pop()
            .expect("Should contain at least one opaque message");

        Ok(message)
    }

    /// Prepares data for encryption.
    ///
    /// # Arguments
    ///
    /// * `role` - The role, either leader or follower.
    /// * `vm` - The virtual machine.
    /// * `seq` - The TLS sequence number.
    /// * `message` - The message to encrypt.
    fn prepare_encrypt<V>(
        role: TlsRole,
        vm: &mut V,
        seq: u64,
        message: EncryptRecord,
    ) -> Result<EncryptRequest, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let EncryptRecord {
            info: msg,
            visibility,
        } = message;

        let (len, plaintext, typ, version) = match msg {
            EncryptInfo::Message(msg) => (
                msg.payload.0.len(),
                Some(msg.payload.0),
                msg.typ,
                msg.version,
            ),
            EncryptInfo::Length(len) => (
                len,
                None,
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
            ),
        };

        let explicit_nonce = seq.to_be_bytes();
        let aad = make_tls12_aad(seq, typ, version, len);

        let plaintext_ref: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        match visibility {
            Visibility::Private => match role {
                TlsRole::Leader => vm.mark_private(plaintext_ref).map_err(MpcTlsError::vm)?,
                TlsRole::Follower => vm.mark_blind(plaintext_ref).map_err(MpcTlsError::vm)?,
            },
            Visibility::Public => vm.mark_public(plaintext_ref).map_err(MpcTlsError::vm)?,
        }

        let encrypt = EncryptRequest {
            plaintext,
            plaintext_ref,
            typ,
            version,
            explicit_nonce,
            aad,
        };
        Ok(encrypt)
    }
}

/// Wrapper for TLS records that need to be encrypted.
pub(crate) struct EncryptRecord {
    pub(crate) info: EncryptInfo,
    pub(crate) visibility: Visibility,
}

/// Either contains the message or the length of the message.
pub(crate) enum EncryptInfo {
    Message(PlainMessage),
    Length(usize),
}

/// Contains data for encryption.
pub(crate) struct EncryptRequest {
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) plaintext_ref: Vector<U8>,
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: [u8; 8],
    pub(crate) aad: [u8; 13],
}

/// Inner state of [`Encrypter`].
enum EncryptState<Sc> {
    Init {
        ghash: Ghash<Sc>,
    },
    Prepared {
        ghash: Ghash<Sc>,
        keystream: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    },
    Ready(AesGcmEncrypt),
    Error,
}

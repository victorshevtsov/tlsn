use crate::{
    decode::OneTimePadShared,
    record_layer::aead::{encrypt::AesGcmEncrypt, ghash::Ghash},
    transcript::Transcript,
    EncryptInfo, EncryptRecord, MpcTlsError, TlsRole, Visibility,
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
        message::OpaqueMessage,
    },
};

pub struct Encrypter<Sc> {
    role: TlsRole,
    transcript: Transcript,
    state: EncryptState<Sc>,
}

impl<Sc> Encrypter<Sc> {
    pub(crate) fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
            transcript: Transcript::default(),
            state: EncryptState::Init { ghash },
        }
    }

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

        let encrypt = Self::prepare_encrypt(self.role, vm, &mut self.transcript, message)?;

        let mut message = aes.encrypt(vm, ctx, vec![encrypt]).await?;
        let message = message
            .pop()
            .expect("Should contain at least one opaque message");

        Ok(message)
    }

    fn prepare_encrypt<V>(
        role: TlsRole,
        vm: &mut V,
        transcript: &mut Transcript,
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

        let seq = transcript.inc_seq();
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

        transcript.record(typ, plaintext_ref);

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

pub(crate) struct EncryptRequest {
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) plaintext_ref: Vector<U8>,
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: [u8; 8],
    pub(crate) aad: [u8; 13],
}

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

//! TLS record layer.

use crate::{
    decode::OneTimePadShared, transcript::Transcript, DecryptRecord, EncryptRecord, MpcTlsError,
    TlsRole, Visibility,
};
use cipher::{aes::Aes128, Keystream};
use mpz_circuits::types::ToBinaryRepr;
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

pub(crate) mod aead;
use aead::{
    ghash::{Ghash, Tag},
    AesGcmDecrypt, AesGcmEncrypt,
};

pub struct Encrypter<Sc> {
    role: TlsRole,
    transcript: Transcript,
    queue: Vec<EncryptRecord>,
    state: EncryptState<Sc>,
}

impl<Sc> Encrypter<Sc> {
    pub fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
            transcript: Transcript::default(),
            queue: Vec::default(),
            state: EncryptState::Init { ghash },
        }
    }

    pub fn alloc(&mut self) -> Result<(), MpcTlsError>
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

    pub fn prepare(
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
    pub fn sent_bytes(&self) -> usize {
        self.transcript.size()
    }

    pub async fn start<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), MpcTlsError>
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

    pub fn enqueue(&mut self, encrypt: EncryptRecord) {
        self.queue.push(encrypt);
    }

    pub async fn encrypt_all<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
    ) -> Result<Vec<OpaqueMessage>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let EncryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Ready state"));
        };

        let encrypt_records = std::mem::take(&mut self.queue);
        let mut encrypts = Vec::with_capacity(encrypt_records.len());

        for message in encrypt_records {
            let encrypt = Self::prepare_encrypt(self.role, vm, &mut self.transcript, message)?;
            encrypts.push(encrypt);
        }

        let messages = aes.encrypt(vm, ctx, encrypts).await?;

        Ok(messages)
    }

    pub async fn encrypt<V, Ctx>(
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
        let EncryptRecord { msg, visibility } = message;

        let PlainMessage {
            typ,
            version,
            payload,
        } = msg;

        let seq = transcript.inc_seq();
        let len = payload.0.len();
        let explicit_nonce = seq.to_be_bytes();
        let aad = make_tls12_aad(seq, typ, version, len);

        let plaintext = payload.0;
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

struct EncryptRequest {
    plaintext: Vec<u8>,
    plaintext_ref: Vector<U8>,
    typ: ContentType,
    version: ProtocolVersion,
    explicit_nonce: [u8; 8],
    aad: [u8; 13],
}

pub struct Decrypter<Sc> {
    role: TlsRole,
    key: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    transcript: Transcript,
    queue: Vec<DecryptRecord>,
    state: DecryptState<Sc>,
}

impl<Sc> Decrypter<Sc> {
    pub fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
            key: None,
            iv: None,
            transcript: Transcript::default(),
            queue: Vec::default(),
            state: DecryptState::Init { ghash },
        }
    }

    pub fn alloc(&mut self) -> Result<(), MpcTlsError>
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
    pub fn recv_bytes(&self) -> usize {
        self.transcript.size()
    }

    pub fn prepare(
        &mut self,
        keystream: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    ) -> Result<(), MpcTlsError> {
        let DecryptState::Init { ghash, .. } =
            std::mem::replace(&mut self.state, DecryptState::Error)
        else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Init state"));
        };

        self.state = DecryptState::Prepared {
            ghash,
            keystream,
            ghash_key,
        };
        Ok(())
    }

    pub fn set_key_and_iv(&mut self, key: Option<Vec<u8>>, iv: Option<Vec<u8>>) {
        self.key = key;
        self.iv = iv;
    }

    pub async fn start<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), MpcTlsError>
    where
        Sc: ShareConvert<Gf2_128> + Flush<Ctx> + Send,
        Sc: AdditiveToMultiplicative<Gf2_128, Future: Send>,
        Sc: MultiplicativeToAdditive<Gf2_128, Future: Send>,
        Ctx: Context,
    {
        let DecryptState::Prepared {
            mut ghash,
            keystream,
            ghash_key,
        } = std::mem::replace(&mut self.state, DecryptState::Error)
        else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Prepared state"));
        };

        let key = ghash_key.decode().await?;

        ghash.set_key(key)?;
        ghash.flush(ctx).await?;
        let ghash = ghash.finalize()?;

        let aes = AesGcmDecrypt::new(self.role, keystream, ghash);
        self.state = DecryptState::Ready(aes);

        Ok(())
    }

    pub fn enqueue(&mut self, decrypt: DecryptRecord) {
        self.queue.push(decrypt);
    }

    pub async fn decrypt_all<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
    ) -> Result<Option<Vec<PlainMessage>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };

        let decrypt_records = std::mem::take(&mut self.queue);

        let mut decrypts = Vec::with_capacity(decrypt_records.len());
        let mut typs = Vec::with_capacity(decrypt_records.len());

        for message in decrypt_records {
            let (decrypt, typ) = Self::prepare_decrypt(&mut self.transcript, message)?;

            decrypts.push(decrypt);
            typs.push(typ);
        }

        let (messages, plaintext_refs) =
            if let (Some(key), Some(iv)) = (self.key.clone(), self.iv.clone()) {
                aes.decrypt_local(vm, ctx, key, iv, decrypts).await?
            } else {
                aes.decrypt(vm, ctx, decrypts).await?
            };

        //TODO: Prove that plaintext encrypts to ciphertext

        for (&typ, plaintext_ref) in typs.iter().zip(plaintext_refs) {
            self.transcript.record(typ, plaintext_ref);
        }

        Ok(messages)
    }

    pub async fn decrypt<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        message: DecryptRecord,
    ) -> Result<Option<PlainMessage>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state"));
        };
        let (decrypt, typ) = Self::prepare_decrypt(&mut self.transcript, message)?;

        let (messages, mut plaintext_refs) =
            if let (Some(key), Some(iv)) = (self.key.clone(), self.iv.clone()) {
                aes.decrypt_local(vm, ctx, key, iv, vec![decrypt]).await?
            } else {
                aes.decrypt(vm, ctx, vec![decrypt]).await?
            };

        let plaintext_ref = plaintext_refs
            .pop()
            .expect("Plaintext references should not be empty");

        let message =
            messages.map(|mut m| m.pop().expect("Should contain at least one opaque message"));

        //TODO: Prove that plaintext encrypts to ciphertext

        self.transcript.record(typ, plaintext_ref);
        Ok(message)
    }

    fn prepare_decrypt(
        transcript: &mut Transcript,
        message: DecryptRecord,
    ) -> Result<(DecryptRequest, ContentType), MpcTlsError> {
        let DecryptRecord { msg, visibility } = message;

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;

        let mut ciphertext = payload.0;

        let seq = transcript.inc_seq();
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

    /// Proves the plaintext of the message to the other party
    ///
    /// This verifies the tag of the message and locally decrypts it. Then, this
    /// party commits to the plaintext and proves it encrypts back to the
    /// ciphertext.
    pub(crate) async fn prove_plaintext(
        &mut self,
        _msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        // TODO
        // 1: Locally decrypt
        // 2: Prove plaintext re-encrypts back to ciphertext
        todo!()
    }

    /// Verifies the plaintext of the message
    ///
    /// This verifies the tag of the message then has the other party decrypt
    /// it. Then, the other party commits to the plaintext and proves it
    /// encrypts back to the ciphertext.
    pub(crate) async fn verify_plaintext(
        &mut self,
        _msg: OpaqueMessage,
    ) -> Result<(), MpcTlsError> {
        // TODO
        // 1: Verify plaintext re-encrypts back to ciphertext
        todo!()
    }
}

enum DecryptState<Sc> {
    Init {
        ghash: Ghash<Sc>,
    },
    Prepared {
        ghash: Ghash<Sc>,
        keystream: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    },
    Ready(AesGcmDecrypt),
    Error,
}

struct DecryptRequest {
    ciphertext: Vec<u8>,
    typ: ContentType,
    visibility: Visibility,
    version: ProtocolVersion,
    explicit_nonce: [u8; 8],
    aad: [u8; 13],
    purported_tag: Tag,
}

//! TLS record layer.

use crate::{
    decode::OneTimePadShared, transcript::Transcript, DecryptRecord, EncryptRecord, MpcTlsError,
    TlsRole, Visibility,
};
use cipher::{aes::Aes128, Keystream};
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Vector, View, ViewExt,
};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::Vm;
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        enums::{ContentType, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    },
};

pub(crate) mod aead;
use aead::{ghash::Tag, AesGcmDecrypt, AesGcmEncrypt, Decrypt, Encrypt};

use self::aead::ghash::Ghash;

pub(crate) struct Encrypter<Sc> {
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
            return Err(MpcTlsError::encrypt("Encrypter is not in Init state."));
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
            return Err(MpcTlsError::encrypt("Encrypter is not in Init state."));
        };

        self.state = EncryptState::Prepared {
            ghash,
            keystream,
            ghash_key,
        };
        Ok(())
    }

    pub async fn setup<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), MpcTlsError>
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
            return Err(MpcTlsError::encrypt("Encrypter is not in Prepared state."));
        };

        let key = ghash_key.decode().await?;

        ghash.set_key(key)?;
        ghash.flush(ctx).await?;
        let ghash = ghash.finalize()?;

        let aes = AesGcmEncrypt::new(self.role, keystream, ghash);
        self.state = EncryptState::Ready(aes);

        Ok(())
    }

    pub fn push(&mut self, encrypt: EncryptRecord) {
        self.queue.push(encrypt);
    }

    fn encrypt<V>(&mut self, vm: &mut V) -> Result<Encrypt, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let EncryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::encrypt("Encrypter is not in Ready state."));
        };

        let encrypt_records = std::mem::take(&mut self.queue);

        let mut encrypts = Vec::with_capacity(encrypt_records.len());
        for record in encrypt_records {
            let EncryptRecord { msg, visibility } = record;

            let PlainMessage {
                typ,
                version,
                payload,
            } = msg;

            let seq = self.transcript.seq();
            let len = payload.0.len();
            let explicit_nonce = seq.to_be_bytes();
            let aad = make_tls12_aad(seq, typ, version, len);

            let plaintext = payload.0;
            let plaintext_ref: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
            match visibility {
                Visibility::Private => match self.role {
                    TlsRole::Leader => vm.mark_private(plaintext_ref).map_err(MpcTlsError::vm)?,
                    TlsRole::Follower => vm.mark_blind(plaintext_ref).map_err(MpcTlsError::vm)?,
                },
                Visibility::Public => vm.mark_public(plaintext_ref).map_err(MpcTlsError::vm)?,
            }

            self.transcript.record(typ, plaintext_ref);
            let encrypt = EncryptRequest {
                plaintext,
                plaintext_ref,
                typ,
                version,
                explicit_nonce,
                aad,
            };
            encrypts.push(encrypt);
        }

        let encrypt = aes.encrypt(vm, encrypts)?;
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

pub(crate) struct Decrypter<Sc> {
    role: TlsRole,
    transcript: Transcript,
    queue: Vec<DecryptRecord>,
    state: DecryptState<Sc>,
}

impl<Sc> Decrypter<Sc> {
    pub fn new(role: TlsRole, ghash: Ghash<Sc>) -> Self {
        Self {
            role,
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
            return Err(MpcTlsError::decrypt("Decrypter is not in Init state."));
        };

        ghash.alloc()?;
        Ok(())
    }

    pub fn prepare(
        &mut self,
        keystream: Keystream<Aes128>,
        ghash_key: OneTimePadShared,
    ) -> Result<(), MpcTlsError> {
        let DecryptState::Init { ghash, .. } =
            std::mem::replace(&mut self.state, DecryptState::Error)
        else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Init state."));
        };

        self.state = DecryptState::Prepared {
            ghash,
            keystream,
            ghash_key,
        };
        Ok(())
    }

    pub async fn setup<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), MpcTlsError>
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
            return Err(MpcTlsError::decrypt("Decrypter is not in Prepared state."));
        };

        let key = ghash_key.decode().await?;

        ghash.set_key(key)?;
        ghash.flush(ctx).await?;
        let ghash = ghash.finalize()?;

        let aes = AesGcmDecrypt::new(self.role, keystream, ghash);
        self.state = DecryptState::Ready(aes);

        Ok(())
    }

    pub fn push(&mut self, decrypt: DecryptRecord) {
        self.queue.push(decrypt);
    }

    fn decrypt<V>(&mut self, vm: &mut V) -> Result<Decrypt, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let DecryptState::Ready(ref mut aes) = self.state else {
            return Err(MpcTlsError::decrypt("Decrypter is not in Ready state."));
        };

        let decrypt_records = std::mem::take(&mut self.queue);

        let mut decrypts = Vec::with_capacity(decrypt_records.len());
        let mut typs = Vec::with_capacity(decrypt_records.len());

        for record in decrypt_records {
            let DecryptRecord { msg, visibility } = record;

            let OpaqueMessage {
                typ,
                version,
                payload,
            } = msg;

            let mut ciphertext = payload.0;

            let seq = self.transcript.seq();
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

            decrypts.push(decrypt);
            typs.push(typ);
        }
        let (decrypt, plaintext_refs) = aes.decrypt(vm, decrypts)?;

        for (&typ, plaintext_ref) in typs.iter().zip(plaintext_refs) {
            self.transcript.record(typ, plaintext_ref);
        }

        Ok(decrypt)
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

/// Proves the plaintext of the message to the other party
///
/// This verifies the tag of the message and locally decrypts it. Then, this
/// party commits to the plaintext and proves it encrypts back to the
/// ciphertext.
pub(crate) async fn prove_plaintext(_msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
    todo!()
}

/// Verifies the plaintext of the message
///
/// This verifies the tag of the message then has the other party decrypt
/// it. Then, the other party commits to the plaintext and proves it
/// encrypts back to the ciphertext.
pub(crate) async fn verify_plaintext(_msg: OpaqueMessage) -> Result<(), MpcTlsError> {
    todo!()
}

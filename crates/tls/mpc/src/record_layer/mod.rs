//! TLS record layer.

use crate::{transcript::Transcript, EncryptRecord, MpcTlsError, TlsRole, Visibility};
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Vector, View, ViewExt,
};
use mpz_vm_core::Vm;
use std::{collections::VecDeque, future::Future};
use tls_core::msgs::enums::ProtocolVersion;
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        base::Payload,
        enums::ContentType,
        message::{OpaqueMessage, PlainMessage},
    },
};

pub(crate) mod aead;
use aead::{AesGcmDecrypt, AesGcmEncrypt, Decrypt, DecryptPrivate, DecryptPublic, Encrypt};

pub(crate) struct Encrypter {
    role: TlsRole,
    transcript: Transcript,
    queue: VecDeque<EncryptRecord>,
    aes: AesGcmEncrypt,
}

impl Encrypter {
    pub fn push(&mut self, encrypt: EncryptRecord) {
        self.queue.push_back(encrypt);
    }

    fn encrypt<V>(&mut self, vm: &mut V) -> Result<Encrypt, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let encrypt_records = Vec::from(std::mem::take(&mut self.queue));

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

        let encrypt = self.aes.encrypt(vm, encrypts)?;
        Ok(encrypt)
    }
}

struct EncryptRequest {
    plaintext: Vec<u8>,
    plaintext_ref: Vector<U8>,
    typ: ContentType,
    version: ProtocolVersion,
    explicit_nonce: [u8; 8],
    aad: [u8; 13],
}

pub(crate) struct Decrypter {
    role: TlsRole,
    transcript: Transcript,
    queue: VecDeque<DecryptRecord>,
    aes: AesGcmDecrypt,
}

impl Decrypter {
    fn decrypt<V>(&mut self, vm: &mut V, msg: OpaqueMessage) -> Result<Decrypt, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
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
        let purported_tag = ciphertext.split_off(ciphertext.len() - 16);
        let len = ciphertext.len();
        let aad = make_tls12_aad(seq, typ, version, len);

        let (decrypt, plaintext_ref) =
            self.aes
                .decrypt(vm, explicit_nonce, ciphertext, aad, purported_tag)?;

        self.transcript.record(typ, plaintext_ref);

        Ok(decrypt)
    }
}

struct DecryptRequest {
    plaintext: Vec<u8>,
    plaintext_ref: Vector<U8>,
    typ: ContentType,
    version: ProtocolVersion,
    explicit_nonce: [u8; 8],
    aad: [u8; 13],
}

/// Proves the plaintext of the message to the other party
///
/// This verifies the tag of the message and locally decrypts it. Then, this
/// party commits to the plaintext and proves it encrypts back to the
/// ciphertext.
pub(crate) async fn prove_plaintext(msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
    todo!()
}

/// Verifies the plaintext of the message
///
/// This verifies the tag of the message then has the other party decrypt
/// it. Then, the other party commits to the plaintext and proves it
/// encrypts back to the ciphertext.
pub(crate) async fn verify_plaintext(msg: OpaqueMessage) -> Result<(), MpcTlsError> {
    todo!()
}

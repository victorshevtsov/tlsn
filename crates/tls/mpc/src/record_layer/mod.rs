//! TLS record layer.

use std::future::Future;

use crate::{transcript::Transcript, MpcTlsError};
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Vector, View, ViewExt,
};
use mpz_vm_core::Vm;
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        base::Payload,
        message::{OpaqueMessage, PlainMessage},
    },
};

pub(crate) mod aead;
use aead::{AesGcmDecrypt, AesGcmEncrypt, Decrypt, DecryptPrivate, DecryptPublic, Encrypt};

use self::aead::ghash::Ghash;

pub(crate) struct Encrypter {
    transcript: Transcript,
    aes: AesGcmEncrypt,
}

impl Encrypter {
    pub(crate) fn encrypt_private<V>(
        &mut self,
        vm: &mut V,
        msg: PlainMessage,
    ) -> Result<Encrypt<impl Future<Output = Result<OpaqueMessage, MpcTlsError>>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        self.encrypt(vm, msg, ViewExt::mark_private)
    }

    pub(crate) fn encrypt_public<V>(
        &mut self,
        vm: &mut V,
        msg: PlainMessage,
    ) -> Result<Encrypt<impl Future<Output = Result<OpaqueMessage, MpcTlsError>>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        self.encrypt(vm, msg, ViewExt::mark_public)
    }

    fn encrypt<V, Vis, Err>(
        &mut self,
        vm: &mut V,
        msg: PlainMessage,
        visibility: Vis,
    ) -> Result<Encrypt<impl Future<Output = Result<OpaqueMessage, MpcTlsError>>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Vis: Fn(&mut V, Vector<U8>) -> Result<(), Err>,
        Err: std::error::Error + Send + Sync + 'static,
    {
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
        visibility(vm, plaintext_ref).map_err(MpcTlsError::vm)?;

        let encrypt = self
            .aes
            .encrypt(vm, plaintext_ref, explicit_nonce, plaintext, aad)?;

        self.transcript.record(typ, plaintext_ref);

        let encrypt = encrypt.map_cipher(move |ciphertext| {
            let mut payload = explicit_nonce.to_vec();
            payload.extend(ciphertext);

            OpaqueMessage {
                typ,
                version,
                payload: Payload::new(payload),
            }
        });

        Ok(encrypt)
    }
}

pub(crate) struct Decrypter {
    transcript: Transcript,
    aes: AesGcmDecrypt,
}

impl Decrypter {
    pub(crate) fn decrypt_private<V>(
        &mut self,
        vm: &mut V,
        msg: OpaqueMessage,
    ) -> Result<
        DecryptPrivate<impl Future<Output = Result<Option<PlainMessage>, MpcTlsError>>>,
        MpcTlsError,
    >
    where
        V: Vm<Binary> + View<Binary>,
    {
        let typ = msg.typ;
        let version = msg.version;

        let decrypt = self.decrypt(vm, msg)?;
        let decrypt = decrypt.private(vm)?;

        let decrypt = decrypt.map_plain(move |plaintext| {
            plaintext.map(|p| PlainMessage {
                typ,
                version,
                payload: Payload(p),
            })
        });

        Ok(decrypt)
    }

    pub(crate) fn decrypt_public<V>(
        &mut self,
        vm: &mut V,
        msg: OpaqueMessage,
    ) -> Result<DecryptPublic<impl Future<Output = Result<PlainMessage, MpcTlsError>>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let typ = msg.typ;
        let version = msg.version;

        let decrypt = self.decrypt(vm, msg)?;
        let decrypt = decrypt.public(vm)?;

        let decrypt = decrypt.map_plain(move |plaintext| PlainMessage {
            typ,
            version,
            payload: Payload::new(plaintext),
        });

        Ok(decrypt)
    }

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

pub(crate) async fn decode_key_private() -> Result<(), MpcTlsError> {
    todo!()
}

pub(crate) async fn decode_key_blind() -> Result<(), MpcTlsError> {
    todo!()
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

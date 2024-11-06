//! TLS record layer.

use crate::{transcript::Transcript, MpcTlsError};
use futures::TryFutureExt;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Vector, View,
};
use mpz_vm_core::Vm;
use std::future::Future;
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        base::Payload,
        message::{OpaqueMessage, PlainMessage},
    },
};

pub(crate) mod aead;
use aead::AesGcmEncrypt;

pub(crate) struct Encrypter {
    transcript: Transcript,
    aes: AesGcmEncrypt,
}

impl Encrypter {
    pub(crate) fn encrypt<V, Vis, Err>(
        &mut self,
        vm: &mut V,
        msg: PlainMessage,
        visibility: Vis,
    ) -> Result<impl Future<Output = Result<OpaqueMessage, MpcTlsError>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Vis: FnOnce(&mut V, Vector<U8>) -> Result<(), Err>,
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

        let (encrypt, cipher_ref) =
            self.aes
                .encrypt(vm, plaintext_ref, explicit_nonce, plaintext, aad)?;

        self.transcript.record(typ, cipher_ref);

        let encrypt = encrypt
            .map_cipher(move |ciphertext| {
                let mut payload = explicit_nonce.to_vec();
                payload.extend(ciphertext);

                OpaqueMessage {
                    typ,
                    version,
                    payload: Payload::new(payload),
                }
            })
            .map_err(MpcTlsError::decode);

        Ok(encrypt)
    }
}

pub(crate) async fn decrypt_private(msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
    todo!()
}

pub(crate) async fn decrypt_blind(msg: OpaqueMessage) -> Result<(), MpcTlsError> {
    todo!()
}

pub(crate) async fn decrypt_public(msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
    todo!()
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

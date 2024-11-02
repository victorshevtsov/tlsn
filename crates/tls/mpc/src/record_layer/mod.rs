//! TLS record layer.

use crate::{transcript::Transcript, MpcTlsError, TlsRole};
use cipher::{CipherCircuit, Keystream};
use mpz_circuits::types::ToBinaryRepr;
use mpz_memory_core::{binary::Binary, Memory, MemoryExt, View, ViewExt};
use mpz_vm_core::{Vm, VmExt};
use tls_core::{
    cipher::make_tls12_aad,
    msgs::{
        base::Payload,
        enums::{ContentType, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    },
};

mod aead;
use aead::encrypt::{prepare_tag_for_encrypt, TagCreator};

const START_COUNTER: u32 = 2;

pub(crate) async fn encrypt_private<V, C>(
    vm: &mut V,
    role: TlsRole,
    transcript: &mut Transcript,
    keystream: &mut Keystream<C>,
    msg: PlainMessage,
) -> Result<OpaqueMessage, MpcTlsError>
where
    V: Vm<Binary> + View<Binary>,
    C: CipherCircuit,
{
    let PlainMessage {
        typ,
        version,
        payload,
    } = msg;

    let (seq, _) = transcript.seq();
    let len = payload.0.len();
    let explicit_nonce = seq.to_be_bytes().to_vec();
    let aad = make_tls12_aad(seq, typ, version, len);
    let plaintext = payload.0;

    let plaintext_ref = vm.alloc().map_err(MpcTlsError::vm)?;
    vm.mark_private(plaintext_ref);

    let keystream = keystream.chunk_sufficient(plaintext.len())?;
    let cipher_out = keystream.apply(vm, plaintext_ref)?;
    let ciphertext = cipher_out.assign(vm, explicit_nonce.clone(), START_COUNTER, plaintext)?;

    transcript.record_sent(typ, ciphertext);

    let j0 = keystream.j0(vm, explicit_nonce.clone())?;
    let tag prepare_tag_for_encrypt(vm, role, j0, ciphertext, aad)
    // TODO: Encrypt here


    let mut payload = explicit_nonce;
    payload.extend(ciphertext);

    Ok(OpaqueMessage {
        typ,
        version,
        payload: Payload::new(payload),
    })
}

pub(crate) async fn encrypt_blind(
    &mut self,
    typ: ContentType,
    version: ProtocolVersion,
    len: usize,
) -> Result<(), MpcTlsError> {
    todo!()
}

pub(crate) async fn encrypt_public(
    &mut self,
    msg: PlainMessage,
) -> Result<OpaqueMessage, MpcTlsError> {
    let PlainMessage {
        typ,
        version,
        payload,
    } = msg;

    self.prepare_encrypt(typ);

    let seq = self.seq;
    let len = payload.0.len();
    let explicit_nonce = seq.to_be_bytes().to_vec();
    let aad = make_tls12_aad(seq, typ, version, len);

    let ciphertext = self
        .aead
        .encrypt_public(explicit_nonce.clone(), payload.0, aad.to_vec())
        .await
        .map_err(|e| MpcTlsError::new_with_source(Kind::Encrypt, "encrypt_public error", e))?;

    self.record_message(typ, len);

    let mut payload = explicit_nonce;
    payload.extend(ciphertext);

    Ok(OpaqueMessage {
        typ,
        version,
        payload: Payload::new(payload),
    })
}

pub(crate) struct Decrypter {
    aead: Box<dyn aead::Aead<Error = AesGcmError>>,
    seq: u64,
    recv_bytes: usize,
    transcript_id: String,
    opaque_transcript_id: String,
}

impl Decrypter {
    pub(crate) fn new(
        aead: Box<dyn aead::Aead<Error = AesGcmError>>,
        transcript_id: String,
        opaque_transcript_id: String,
    ) -> Self {
        Self {
            aead,
            seq: 0,
            recv_bytes: 0,
            transcript_id,
            opaque_transcript_id,
        }
    }

    /// Returns the number of application data bytes decrypted
    pub(crate) fn recv_bytes(&self) -> usize {
        self.recv_bytes
    }

    pub(crate) async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), MpcTlsError> {
        self.aead.set_key(key, iv).await.map_err(|e| {
            MpcTlsError::new_with_source(Kind::Decrypt, "error setting decryption key", e)
        })?;

        Ok(())
    }

    pub(crate) async fn preprocess(&mut self, len: usize) -> Result<(), MpcTlsError> {
        self.aead
            .preprocess(len)
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "preprocess error", e))?;

        Ok(())
    }

    pub(crate) async fn setup(&mut self) -> Result<(), MpcTlsError> {
        self.aead
            .setup()
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "setup error", e))?;

        Ok(())
    }

    pub(crate) async fn start(&mut self) -> Result<(), MpcTlsError> {
        self.aead
            .start()
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "start error", e))?;

        Ok(())
    }

    pub(crate) async fn decrypt_private(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        let OpaqueMessage {
            typ,
            version,
            mut payload,
        } = msg;

        let explicit_nonce: Vec<u8> = payload.0.drain(..8).collect();
        let len = payload.0.len() - 16;
        let seq = self.seq;

        self.prepare_decrypt(typ);

        let aad = make_tls12_aad(seq, typ, version, len);
        let plaintext = self
            .aead
            .decrypt_private(explicit_nonce, payload.0, aad.to_vec())
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "decrypt_private error", e))?;

        self.record_message(typ, len);

        Ok(PlainMessage {
            typ,
            version,
            payload: Payload::new(plaintext),
        })
    }

    pub(crate) async fn decrypt_blind(&mut self, msg: OpaqueMessage) -> Result<(), MpcTlsError> {
        let OpaqueMessage {
            typ,
            version,
            mut payload,
        } = msg;

        let explicit_nonce: Vec<u8> = payload.0.drain(..8).collect();
        let len = payload.0.len() - 16;
        let seq = self.seq;

        self.prepare_decrypt(typ);

        let aad = make_tls12_aad(seq, typ, version, len);
        self.aead
            .decrypt_blind(explicit_nonce, payload.0, aad.to_vec())
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "decrypt_blind error", e))?;

        self.record_message(typ, len);

        Ok(())
    }

    pub(crate) async fn decrypt_public(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        let OpaqueMessage {
            typ,
            version,
            mut payload,
        } = msg;

        let explicit_nonce: Vec<u8> = payload.0.drain(..8).collect();
        let len = payload.0.len() - 16;
        let seq = self.seq;

        self.prepare_decrypt(typ);

        let aad = make_tls12_aad(seq, typ, version, len);
        let plaintext = self
            .aead
            .decrypt_public(explicit_nonce, payload.0, aad.to_vec())
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "decrypt_public error", e))?;

        self.record_message(typ, len);

        Ok(PlainMessage {
            typ,
            version,
            payload: Payload::new(plaintext),
        })
    }

    pub(crate) async fn decode_key_private(&mut self) -> Result<(), MpcTlsError> {
        self.aead
            .decode_key_private()
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "error decoding key", e))
    }

    pub(crate) async fn decode_key_blind(&mut self) -> Result<(), MpcTlsError> {
        self.aead
            .decode_key_blind()
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "error decoding key", e))
    }

    /// Proves the plaintext of the message to the other party
    ///
    /// This verifies the tag of the message and locally decrypts it. Then, this
    /// party commits to the plaintext and proves it encrypts back to the
    /// ciphertext.
    pub(crate) async fn prove_plaintext(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        let OpaqueMessage {
            typ,
            version,
            mut payload,
        } = msg;

        let explicit_nonce: Vec<u8> = payload.0.drain(..8).collect();
        let len = payload.0.len() - 16;
        let seq = self.seq;

        self.prepare_decrypt(typ);

        let aad = make_tls12_aad(seq, typ, version, len);
        let plaintext = self
            .aead
            .prove_plaintext(explicit_nonce, payload.0, aad.to_vec())
            .await
            .map_err(|e| MpcTlsError::new_with_source(Kind::Decrypt, "prove_plaintext error", e))?;

        self.record_message(typ, len);

        Ok(PlainMessage {
            typ,
            version,
            payload: Payload::new(plaintext),
        })
    }

    /// Verifies the plaintext of the message
    ///
    /// This verifies the tag of the message then has the other party decrypt
    /// it. Then, the other party commits to the plaintext and proves it
    /// encrypts back to the ciphertext.
    pub(crate) async fn verify_plaintext(&mut self, msg: OpaqueMessage) -> Result<(), MpcTlsError> {
        let OpaqueMessage {
            typ,
            version,
            mut payload,
        } = msg;

        let explicit_nonce: Vec<u8> = payload.0.drain(..8).collect();
        let len = payload.0.len() - 16;
        let seq = self.seq;

        self.prepare_decrypt(typ);

        let aad = make_tls12_aad(seq, typ, version, len);
        self.aead
            .verify_plaintext(explicit_nonce, payload.0, aad.to_vec())
            .await
            .map_err(|e| {
                MpcTlsError::new_with_source(Kind::Decrypt, "verify_plaintext error", e)
            })?;

        self.record_message(typ, len);

        Ok(())
    }

    fn prepare_decrypt(&mut self, typ: ContentType) {
        // Set the transcript id depending on the type of message
        match typ {
            ContentType::ApplicationData => {
                self.aead.set_transcript_id(&self.transcript_id);
            }
            _ => self.aead.set_transcript_id(&self.opaque_transcript_id),
        }
    }

    fn record_message(&mut self, typ: ContentType, len: usize) {
        self.seq += 1;
        if let ContentType::ApplicationData = typ {
            self.recv_bytes += len;
        }
    }
}

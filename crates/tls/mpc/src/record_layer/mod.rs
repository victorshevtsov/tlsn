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

pub(crate) mod aead;

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
    todo!()
    //  let PlainMessage {
    //      typ,
    //      version,
    //      payload,
    //  } = msg;

    //  let (seq, _) = transcript.seq();
    //  let len = payload.0.len();
    //  let explicit_nonce = seq.to_be_bytes().to_vec();
    //  let aad = make_tls12_aad(seq, typ, version, len);
    //  let plaintext = payload.0;

    //  let plaintext_ref = vm.alloc().map_err(MpcTlsError::vm)?;
    //  vm.mark_private(plaintext_ref);

    //  let keystream = keystream.chunk_sufficient(plaintext.len())?;
    //  let cipher_out = keystream.apply(vm, plaintext_ref)?;
    //  let ciphertext = cipher_out.assign(vm, explicit_nonce.clone(), START_COUNTER, plaintext)?;

    //  transcript.record_sent(typ, ciphertext);

    //  let j0 = keystream.j0(vm, explicit_nonce.clone())?;
    //  let tag prepare_tag_for_encrypt(vm, role, j0, ciphertext, aad)
    //  // TODO: Encrypt here

    //  let mut payload = explicit_nonce;
    //  payload.extend(ciphertext);

    //  Ok(OpaqueMessage {
    //      typ,
    //      version,
    //      payload: Payload::new(payload),
    //  })
}

pub(crate) async fn encrypt_blind(
    typ: ContentType,
    version: ProtocolVersion,
    len: usize,
) -> Result<(), MpcTlsError> {
    todo!()
}

pub(crate) async fn encrypt_public(msg: PlainMessage) -> Result<OpaqueMessage, MpcTlsError> {
    todo!()
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

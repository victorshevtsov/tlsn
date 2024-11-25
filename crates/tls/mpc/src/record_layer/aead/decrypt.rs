use crate::{
    decode::{Decode, OneTimePadPrivate, OneTimePadShared},
    record_layer::{
        aead::{
            ghash::{GhashCompute, Tag, TagBatch, TagComputer},
            transmute, START_COUNTER,
        },
        DecryptRequest,
    },
    MpcTlsError, TlsRole, Visibility,
};
use cipher::{aes::Aes128, Keystream};
use futures::{stream::FuturesOrdered, StreamExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, MemoryExt, Vector, View, ViewExt,
};
use mpz_vm_core::Vm;
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::PlainMessage,
};
use tracing::instrument;

pub(crate) struct AesGcmDecrypt {
    role: TlsRole,
    keystream: Keystream<Aes128>,
    ghash: GhashCompute,
}

impl AesGcmDecrypt {
    /// Preparation for decrypting a ciphertext.
    ///
    /// Returns [`Decrypt`] and plaintext refs.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `requests` - Decryption requests.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) fn decrypt<V>(
        &mut self,
        vm: &mut V,
        requests: Vec<DecryptRequest>,
    ) -> Result<(Decrypt, Vec<Vector<U8>>), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let len = requests.len();
        let mut decrypt = Decrypt::new(self.role, self.ghash.clone(), len);
        let mut plaintext_refs = Vec::with_capacity(len);

        for DecryptRequest {
            ciphertext,
            typ,
            visibility,
            version,
            explicit_nonce,
            aad,
            purported_tag,
        } in requests
        {
            let j0 = self.keystream.j0(vm, explicit_nonce)?;
            let j0 = Decode::new(vm, self.role, transmute(j0))?;
            let j0 = j0.shared(vm)?;

            let keystream = self.keystream.chunk_sufficient(ciphertext.len())?;
            let cipher_ref: Vector<U8> = vm.alloc_vec(ciphertext.len()).map_err(MpcTlsError::vm)?;
            vm.mark_public(cipher_ref).map_err(MpcTlsError::vm)?;

            let cipher_out = keystream.apply(vm, cipher_ref).map_err(MpcTlsError::vm)?;
            let plaintext_ref = cipher_out
                .assign(vm, explicit_nonce, START_COUNTER, ciphertext.clone())
                .map_err(MpcTlsError::vm)?;

            let decode = match visibility {
                Visibility::Private => {
                    DecryptDecode::Private(Decode::new(vm, self.role, plaintext_ref)?.private(vm)?)
                }
                Visibility::Public => {
                    DecryptDecode::Public(vm.decode(plaintext_ref).map_err(MpcTlsError::decode)?)
                }
            };

            plaintext_refs.push(plaintext_ref);
            decrypt.push(j0, ciphertext, decode, typ, version, aad, purported_tag);
        }

        Ok((decrypt, plaintext_refs))
    }
}

/// A struct for decryption operations.
pub(crate) struct Decrypt {
    role: TlsRole,
    ghash: GhashCompute,
    j0s: Vec<OneTimePadShared>,
    ciphertexts: Vec<Vec<u8>>,
    decodes: Vec<DecryptDecode>,
    typs: Vec<ContentType>,
    versions: Vec<ProtocolVersion>,
    aads: Vec<[u8; 13]>,
    purported_tags: Vec<Tag>,
}

impl Decrypt {
    /// Creates a new instance.
    pub(crate) fn new(role: TlsRole, ghash: GhashCompute, cap: usize) -> Self {
        Self {
            role,
            ghash,
            j0s: Vec::with_capacity(cap),
            ciphertexts: Vec::with_capacity(cap),
            decodes: Vec::with_capacity(cap),
            typs: Vec::with_capacity(cap),
            versions: Vec::with_capacity(cap),
            aads: Vec::with_capacity(cap),
            purported_tags: Vec::with_capacity(cap),
        }
    }

    /// Adds a decrypt operation.
    pub(crate) fn push(
        &mut self,
        j0: OneTimePadShared,
        ciphertext: Vec<u8>,
        decode: DecryptDecode,
        typ: ContentType,
        version: ProtocolVersion,
        aad: [u8; 13],
        purported_tag: Tag,
    ) {
        self.j0s.push(j0);
        self.ciphertexts.push(ciphertext);
        self.decodes.push(decode);
        self.typs.push(typ);
        self.versions.push(version);
        self.aads.push(aad);
        self.purported_tags.push(purported_tag);
    }

    /// Returns the number of records this instance will decrypt.
    pub(crate) fn len(&self) -> usize {
        self.ciphertexts.len()
    }

    /// Computes the plaintext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    pub(crate) async fn compute<Ctx>(
        self,
        ctx: &mut Ctx,
    ) -> Result<Vec<Option<PlainMessage>>, MpcTlsError>
    where
        Ctx: Context,
    {
        let len = self.len();

        let j0s = self.j0s.into_iter().map(|j0| j0.decode());
        let plaintexts = self.decodes.into_iter().map(|p| p.decode());

        let mut future: FuturesOrdered<_> = j0s
            .zip(plaintexts)
            .map(|(j0, plaintext)| futures::future::try_join(j0, plaintext))
            .collect();

        let mut j0s = Vec::with_capacity(len);
        let mut plaintexts = Vec::with_capacity(len);

        while let Some(result) = future.next().await {
            let (j0, plaintext) = result?;
            j0s.push(j0);
            plaintexts.push(plaintext);
        }

        let tags =
            TagComputer::new(j0s, self.ciphertexts.clone(), self.aads).compute(&self.ghash)?;
        tags.verify(ctx, self.role, TagBatch::new(self.purported_tags))
            .await?;

        let output = self
            .typs
            .into_iter()
            .zip(self.versions)
            .zip(plaintexts)
            .map(|((typ, version), ciphertext)| {
                ciphertext.map(|c| PlainMessage {
                    typ,
                    version,
                    payload: Payload(c),
                })
            })
            .collect();

        Ok(output)
    }
}

enum DecryptDecode {
    Private(OneTimePadPrivate),
    Public(DecodeFutureTyped<BitVec<u32>, Vec<u8>>),
}

impl DecryptDecode {
    async fn decode(self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        match self {
            DecryptDecode::Private(plaintext) => plaintext.decode().await,
            DecryptDecode::Public(plaintext) => {
                plaintext.await.map(Some).map_err(MpcTlsError::decode)
            }
        }
    }
}

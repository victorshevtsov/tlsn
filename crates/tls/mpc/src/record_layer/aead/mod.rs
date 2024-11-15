//! Handles authenticated encryption, decryption and tags.

use crate::{
    decode::{Decode, OneTimePadPrivate, OneTimePadShared},
    record_layer::EncryptRequest,
    MpcTlsError, TlsRole, Visibility,
};
use cipher::{aes::Aes128, Keystream};
use futures::{stream::FuturesOrdered, StreamExt, TryFutureExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, FromRaw, Memory, MemoryExt, Slice, StaticSize, ToRaw, Vector, View, ViewExt,
};
use mpz_vm_core::Vm;
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::{OpaqueMessage, PlainMessage},
};
use tracing::instrument;

pub(crate) mod ghash;
use ghash::{GhashCompute, TagComputer};

use self::ghash::{Tag, TagBatch};

use super::DecryptRequest;

const START_COUNTER: u32 = 2;

pub(crate) struct AesGcmEncrypt {
    role: TlsRole,
    keystream: Keystream<Aes128>,
    ghash: GhashCompute,
}

impl AesGcmEncrypt {
    /// Creates a new instance for encryption.
    ///
    /// # Arguments
    ///
    /// * `role` - The role of the party.
    /// * `keystream` - The keystream for AES-GCM.
    /// * `ghash` - An instance for computing Ghash.
    pub(crate) fn new(role: TlsRole, keystream: Keystream<Aes128>, ghash: GhashCompute) -> Self {
        Self {
            role,
            keystream,
            ghash,
        }
    }

    /// Preparation for encrypting a ciphertext.
    ///
    /// Returns [`Encrypt`].
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `requests` - Encryption requests.
    #[allow(clippy::type_complexity)]
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) fn encrypt<V>(
        &mut self,
        vm: &mut V,
        requests: Vec<EncryptRequest>,
    ) -> Result<Encrypt, MpcTlsError>
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary>,
    {
        let len = requests.len();
        let mut encrypt = Encrypt::new(self.ghash.clone(), len);

        for EncryptRequest {
            plaintext,
            plaintext_ref,
            typ,
            version,
            explicit_nonce,
            aad,
        } in requests
        {
            let j0 = self.keystream.j0(vm, explicit_nonce)?;
            let j0 = Decode::new(vm, self.role, transmute(j0))?;
            let j0 = j0.shared(vm)?;

            let keystream = self.keystream.chunk_sufficient(plaintext.len())?;

            let cipher_out = keystream
                .apply(vm, plaintext_ref)
                .map_err(MpcTlsError::vm)?;
            let cipher_ref = cipher_out
                .assign(vm, explicit_nonce, START_COUNTER, plaintext)
                .map_err(MpcTlsError::vm)?;

            let ciphertext = vm.decode(cipher_ref).map_err(MpcTlsError::decode)?;
            encrypt.push(j0, explicit_nonce, ciphertext, typ, version, aad);
        }
        Ok(encrypt)
    }
}

/// A struct for encryption operations.
pub(crate) struct Encrypt {
    ghash: GhashCompute,
    j0s: Vec<OneTimePadShared>,
    explicit_nonces: Vec<[u8; 8]>,
    ciphertexts: Vec<DecodeFutureTyped<BitVec<u32>, Vec<u8>>>,
    typs: Vec<ContentType>,
    versions: Vec<ProtocolVersion>,
    aads: Vec<[u8; 13]>,
}

impl Encrypt {
    /// Creates a new instance.
    pub(crate) fn new(ghash: GhashCompute, cap: usize) -> Self {
        Self {
            ghash,
            j0s: Vec::with_capacity(cap),
            explicit_nonces: Vec::with_capacity(cap),
            ciphertexts: Vec::with_capacity(cap),
            typs: Vec::with_capacity(cap),
            versions: Vec::with_capacity(cap),
            aads: Vec::with_capacity(cap),
        }
    }

    /// Adds an encrypt operation.
    pub(crate) fn push(
        &mut self,
        j0: OneTimePadShared,
        explicit_nonce: [u8; 8],
        ciphertext: DecodeFutureTyped<BitVec<u32>, Vec<u8>>,
        typ: ContentType,
        version: ProtocolVersion,
        aad: [u8; 13],
    ) {
        self.j0s.push(j0);
        self.explicit_nonces.push(explicit_nonce);
        self.ciphertexts.push(ciphertext);
        self.typs.push(typ);
        self.versions.push(version);
        self.aads.push(aad);
    }

    /// Returns the number of records this instance will encrypt.
    pub(crate) fn len(&self) -> usize {
        self.ciphertexts.len()
    }

    /// Computes the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Vec<OpaqueMessage>, MpcTlsError>
    where
        Ctx: Context,
    {
        let len = self.len();

        let j0s = self.j0s.into_iter().map(|j0| j0.decode());
        let ciphertexts = self
            .ciphertexts
            .into_iter()
            .map(|ciphertext| ciphertext.map_err(MpcTlsError::decode));

        let mut future: FuturesOrdered<_> = j0s
            .zip(ciphertexts)
            .map(|(j0, ciphertext)| futures::future::try_join(j0, ciphertext))
            .collect();

        let mut j0s = Vec::with_capacity(len);
        let mut ciphertexts = Vec::with_capacity(len);

        while let Some(result) = future.next().await {
            let (j0, ciphertext) = result?;
            j0s.push(j0);
            ciphertexts.push(ciphertext);
        }

        let tags = TagComputer::new(j0s, ciphertexts.clone(), self.aads)
            .compute(&self.ghash)
            .await?;
        let tags = tags.combine(ctx).await?;

        let output = self
            .explicit_nonces
            .into_iter()
            .zip(self.typs)
            .zip(self.versions)
            .zip(ciphertexts)
            .zip(tags.into_inner())
            .map(|((((nonce, typ), version), ciphertext), tag)| {
                let mut payload = nonce.to_vec();
                payload.extend(ciphertext);
                payload.extend(tag.into_inner());

                OpaqueMessage {
                    typ,
                    version,
                    payload: Payload(payload),
                }
            })
            .collect();

        Ok(output)
    }
}

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

        let tags = TagComputer::new(j0s, self.ciphertexts.clone(), self.aads)
            .compute(&self.ghash)
            .await?;
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

fn transmute<T>(value: T) -> Vector<U8>
where
    T: StaticSize<Binary> + ToRaw,
{
    let ptr = value.to_raw().ptr();
    let size = T::SIZE;
    let slice = Slice::new_unchecked(ptr, size);

    Vector::<U8>::from_raw(slice)
}

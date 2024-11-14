//! Handles authenticated encryption, decryption and tags.

use crate::{
    decode::{Decode, OneTimePadShared},
    record_layer::EncryptRequest,
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use futures::{stream::FuturesOrdered, StreamExt, TryFutureExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeError, MemoryExt, StaticSize, Vector, View, ViewExt,
};
use mpz_memory_core::{DecodeFutureTyped, FromRaw, Memory, Slice, ToRaw};
use mpz_vm_core::Vm;
use std::future::Future;
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::{OpaqueMessage, PlainMessage},
};
use tracing::instrument;

pub(crate) mod ghash;
use ghash::{
    Ghash, GhashCompute, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError, TagComputer,
};

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
    /// Returns [`Encrypt`] for async computation.
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

/// A struct for encryption operation.
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
            .compute(ctx, &self.ghash)
            .await?;

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
    /// Returns [`Decrypt`] for async computation.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `explicit_nonce` - The TLS explicit nonce.
    /// * `ciphertext` - The ciphertext to decrypt.
    /// * `aad` - Additional data for AEAD.
    /// * `purported_tag` - The MAC from the server.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) fn decrypt<V>(
        &mut self,
        vm: &mut V,
        explicit_nonce: [u8; 8],
        ciphertext: Vec<u8>,
        aad: [u8; 13],
        purported_tag: Vec<u8>,
    ) -> Result<(Decrypt, Vector<U8>), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
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

        let decrypt = Decrypt {
            role: self.role,
            j0,
            ciphertext,
            ghash: self.ghash.clone(),
            plaintext_ref,
            aad,
            purported_tag,
        };

        Ok((decrypt, plaintext_ref))
    }
}

/// A struct for decryption operation.
///
/// Can be turned into either [`DecryptPrivate`] or [`DecryptPublic`].
pub(crate) struct Decrypt {
    role: TlsRole,
    j0: OneTimePadShared,
    ciphertext: Vec<u8>,
    ghash: GhashCompute,
    plaintext_ref: Vector<U8>,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl Decrypt {
    /// Turns `self` into [`DecryptPrivate`].
    pub(crate) fn private<V>(
        self,
        vm: &mut V,
    ) -> Result<
        DecryptPrivate<impl Future<Output = Result<Option<Vec<u8>>, MpcTlsError>>>,
        MpcTlsError,
    >
    where
        V: Vm<Binary> + View<Binary>,
    {
        let otp = Decode::new(vm, self.role, self.plaintext_ref)?;
        let plaintext = otp.private(vm)?.decode();

        let decrypt = DecryptPrivate {
            role: self.role,
            j0: self.j0,
            ciphertext: self.ciphertext,
            ghash: self.ghash,
            plaintext,
            aad: self.aad,
            purported_tag: self.purported_tag,
        };

        Ok(decrypt)
    }

    /// Turns `self` into [`DecryptPublic`].
    pub(crate) fn public<V>(
        self,
        vm: &mut V,
    ) -> Result<DecryptPublic<impl Future<Output = Result<Vec<u8>, DecodeError>>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let plaintext = vm.decode(self.plaintext_ref).map_err(MpcTlsError::decode)?;

        let decrypt = DecryptPublic {
            role: self.role,
            j0: self.j0,
            ciphertext: self.ciphertext,
            ghash: self.ghash,
            plaintext,
            aad: self.aad,
            purported_tag: self.purported_tag,
        };

        Ok(decrypt)
    }
}

/// Private decryption.
pub(crate) struct DecryptPrivate<F> {
    role: TlsRole,
    j0: OneTimePadShared,
    ghash: GhashCompute,
    ciphertext: Vec<u8>,
    plaintext: F,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl<F> DecryptPrivate<F> {
    /// Transforms the inner plaintext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_plain<T, U>(
        self,
        func: T,
    ) -> DecryptPrivate<impl Future<Output = Result<U, MpcTlsError>>>
    where
        F: Future<Output = Result<Option<Vec<u8>>, MpcTlsError>>,
        T: FnOnce(Option<Vec<u8>>) -> U,
    {
        DecryptPrivate {
            role: self.role,
            j0: self.j0,
            ghash: self.ghash,
            ciphertext: self.ciphertext,
            plaintext: self.plaintext.map_ok(func),
            aad: self.aad,
            purported_tag: self.purported_tag,
        }
    }

    /// Computes the private plaintext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    pub(crate) async fn compute<Ctx>(
        self,
        ctx: &mut Ctx,
    ) -> Result<Option<PlainMessage>, MpcTlsError>
    where
        F: Future<Output = Result<Option<PlainMessage>, MpcTlsError>>,
        Ctx: Context,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let plaintext = self.plaintext.map_err(MpcTlsError::decode);
        let (j0, plaintext) = futures::try_join!(j0, plaintext)?;

        let tag = Tag::compute(ctx, &self.ghash, j0, &self.ciphertext, aad).await?;
        tag.verify(ctx, self.role, self.purported_tag).await?;

        Ok(plaintext)
    }
}

/// Public decryption.
pub(crate) struct DecryptPublic<F> {
    role: TlsRole,
    j0: OneTimePadShared,
    ghash: GhashCompute,
    ciphertext: Vec<u8>,
    plaintext: F,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl<F> DecryptPublic<F> {
    /// Transforms the inner plaintext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_plain<T, U>(
        self,
        func: T,
    ) -> DecryptPublic<impl Future<Output = Result<U, MpcTlsError>>>
    where
        F: Future<Output = Result<Vec<u8>, DecodeError>>,
        T: FnOnce(Vec<u8>) -> U,
    {
        DecryptPublic {
            role: self.role,
            j0: self.j0,
            ghash: self.ghash,
            ciphertext: self.ciphertext,
            plaintext: self.plaintext.map_ok(func).map_err(MpcTlsError::decode),
            aad: self.aad,
            purported_tag: self.purported_tag,
        }
    }

    /// Computes the public plaintext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<PlainMessage, MpcTlsError>
    where
        Ctx: Context,
        F: Future<Output = Result<PlainMessage, MpcTlsError>>,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let plaintext = self.plaintext.map_err(MpcTlsError::decode);
        let (j0, plaintext) = futures::try_join!(j0, plaintext)?;

        let tag = Tag::compute(ctx, &self.ghash, j0, &self.ciphertext, aad).await?;
        tag.verify(ctx, self.role, self.purported_tag).await?;

        Ok(plaintext)
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

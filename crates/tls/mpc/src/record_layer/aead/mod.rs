//! Handles authenticated encryption, decryption and tags.

use std::future::Future;

use crate::{
    decode::{Decode, OneTimePadShared},
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use futures::{TryFuture, TryFutureExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeError, MemoryExt, StaticSize, Vector, View, ViewExt,
};
use mpz_memory_core::{DecodeFutureTyped, Memory};
use mpz_memory_core::{FromRaw, Slice, ToRaw};
use mpz_vm_core::Vm;

pub(crate) mod ghash;
use ghash::{Ghash, GhashCompute, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError, Tag};
use tracing::instrument;

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
    /// * `plaintext_ref` - The VM plaintext reference.
    /// * `explicit_nonce` - The TLS explicit nonce.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `aad` - Additional data for AEAD.
    #[allow(clippy::type_complexity)]
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) fn encrypt<V>(
        &mut self,
        vm: &mut V,
        plaintext_ref: Vector<U8>,
        explicit_nonce: [u8; 8],
        plaintext: Vec<u8>,
        aad: [u8; 13],
    ) -> Result<Encrypt<'_, DecodeFutureTyped<BitVec<u32>, Vec<u8>>>, MpcTlsError>
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary>,
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
        let encrypt = Encrypt {
            j0,
            ghash: &self.ghash,
            ciphertext,
            aad,
        };

        Ok(encrypt)
    }
}

/// Encrypts a ciphertext.
pub(crate) struct Encrypt<'a, F> {
    j0: OneTimePadShared,
    ghash: &'a GhashCompute,
    ciphertext: F,
    aad: [u8; 13],
}

impl<'a, F> Encrypt<'a, F> {
    /// Transforms the inner ciphertext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_cipher<T, U>(
        self,
        func: T,
    ) -> Encrypt<'a, impl TryFuture<Ok = U, Error = MpcTlsError>>
    where
        T: FnOnce(F::Ok) -> U,
        F: TryFuture<Ok = Vec<u8>, Error = DecodeError>,
    {
        Encrypt {
            j0: self.j0,
            ghash: self.ghash,
            ciphertext: self.ciphertext.map_ok(func).map_err(MpcTlsError::decode),
            aad: self.aad,
        }
    }

    /// Computes the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Vec<u8>, MpcTlsError>
    where
        Ctx: Context,
        F: TryFuture<Ok = Vec<u8>, Error = DecodeError>,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let ciphertext = self.ciphertext.map_err(MpcTlsError::decode);
        let (j0, mut ciphertext) = futures::try_join!(j0, ciphertext)?;

        let tag = Tag::compute(ctx, self.ghash, j0, &ciphertext, aad).await?;
        ciphertext.extend(tag.into_inner());

        Ok(ciphertext)
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
    ) -> Result<(Decrypt<'_>, Vector<U8>), MpcTlsError>
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
            ghash: &self.ghash,
            plaintext_ref,
            aad,
            purported_tag,
        };

        Ok((decrypt, plaintext_ref))
    }
}

pub(crate) struct Decrypt<'a> {
    role: TlsRole,
    j0: OneTimePadShared,
    ciphertext: Vec<u8>,
    ghash: &'a GhashCompute,
    plaintext_ref: Vector<U8>,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl<'a> Decrypt<'a> {
    pub(crate) fn private<V>(
        self,
        vm: &mut V,
    ) -> Result<
        DecryptPrivate<'a, impl Future<Output = Result<Option<Vec<u8>>, MpcTlsError>>>,
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

    pub(crate) fn public<V>(
        self,
        vm: &mut V,
    ) -> Result<DecryptPublic<'a, impl Future<Output = Result<Vec<u8>, DecodeError>>>, MpcTlsError>
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

pub(crate) struct DecryptPrivate<'a, F> {
    role: TlsRole,
    j0: OneTimePadShared,
    ghash: &'a GhashCompute,
    ciphertext: Vec<u8>,
    plaintext: F,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl<'a, F> DecryptPrivate<'a, F>
where
    F: TryFuture<Ok = Option<Vec<u8>>, Error = MpcTlsError>,
{
    /// Transforms the inner plaintext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_plain<T, U>(
        self,
        func: T,
    ) -> DecryptPrivate<'a, impl TryFuture<Ok = U, Error = MpcTlsError>>
    where
        T: FnOnce(F::Ok) -> U,
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

    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Option<Vec<u8>>, MpcTlsError>
    where
        Ctx: Context,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let plaintext = self.plaintext.map_err(MpcTlsError::decode);
        let (j0, plaintext) = futures::try_join!(j0, plaintext)?;

        let tag = Tag::compute(ctx, self.ghash, j0, &self.ciphertext, aad).await?;
        tag.verify(ctx, self.role, self.purported_tag).await?;

        Ok(plaintext)
    }
}

pub(crate) struct DecryptPublic<'a, F> {
    role: TlsRole,
    j0: OneTimePadShared,
    ghash: &'a GhashCompute,
    ciphertext: Vec<u8>,
    plaintext: F,
    aad: [u8; 13],
    purported_tag: Vec<u8>,
}

impl<'a, F> DecryptPublic<'a, F>
where
    F: TryFuture<Ok = Vec<u8>, Error = DecodeError>,
{
    /// Transforms the inner plaintext future with a closure.
    ///
    /// # Arguments
    ///
    /// * `func` - The provided closure.
    pub(crate) fn map_plain<T, U>(
        self,
        func: T,
    ) -> DecryptPublic<'a, impl TryFuture<Ok = U, Error = MpcTlsError>>
    where
        T: FnOnce(F::Ok) -> U,
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

    pub(crate) async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Vec<u8>, MpcTlsError>
    where
        Ctx: Context,
    {
        let j0 = self.j0.decode().map_err(MpcTlsError::decode);
        let aad = self.aad.to_vec();
        let plaintext = self.plaintext.map_err(MpcTlsError::decode);
        let (j0, plaintext) = futures::try_join!(j0, plaintext)?;

        let tag = Tag::compute(ctx, self.ghash, j0, &self.ciphertext, aad).await?;
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

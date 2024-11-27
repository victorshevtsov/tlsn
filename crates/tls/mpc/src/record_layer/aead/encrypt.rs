use crate::{
    decode::{Decode, OneTimePadShared},
    record_layer::{
        aead::{
            ghash::{GhashCompute, TagComputer},
            transmute, START_COUNTER,
        },
        EncryptRequest,
    },
    MpcTlsError, TlsRole,
};
use cipher::{aes::Aes128, Keystream};
use futures::{stream::FuturesOrdered, StreamExt, TryFutureExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{binary::Binary, DecodeFutureTyped, Memory, MemoryExt, View};
use mpz_vm_core::{Execute, Vm};
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::OpaqueMessage,
};
use tracing::instrument;

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

    /// Encrypts a plaintext.
    ///
    /// Returns [`Encrypt`].
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `ctx` - The context for IO.
    /// * `requests` - Encryption requests.
    #[allow(clippy::type_complexity)]
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn encrypt<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        requests: Vec<EncryptRequest>,
    ) -> Result<Vec<OpaqueMessage>, MpcTlsError>
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
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

        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        let messages = encrypt.compute(ctx).await?;

        Ok(messages)
    }
}

/// A struct for encryption operations.
struct Encrypt {
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
    fn new(ghash: GhashCompute, cap: usize) -> Self {
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
    fn push(
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
    fn len(&self) -> usize {
        self.ciphertexts.len()
    }

    /// Computes the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    #[instrument(level = "trace", skip_all, err)]
    async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Vec<OpaqueMessage>, MpcTlsError>
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

        let tags = TagComputer::new(j0s, ciphertexts.clone(), self.aads).compute(&self.ghash)?;
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

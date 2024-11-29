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
use cipher::{aes::Aes128, Input, Keystream};
use futures::{stream::FuturesOrdered, StreamExt};
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, MemoryExt, Vector, View, ViewExt,
};
use mpz_vm_core::{Execute, Vm};
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::PlainMessage,
};
use tracing::instrument;

pub(crate) struct AesGcmDecrypt {
    role: TlsRole,
    key: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    keystream_mpc: Keystream<Aes128>,
    keystream_zk: Keystream<Aes128>,
    ghash: GhashCompute,
}

impl AesGcmDecrypt {
    /// Creates a new instance for decryption.
    ///
    /// # Arguments
    ///
    /// * `role` - The role of the party.
    /// * `keystream_mpc` - The keystream for MPC AES-GCM.
    /// * `keystream_zk` - The keystream for ZK AES-GCM.
    /// * `ghash` - An instance for computing Ghash.
    pub(crate) fn new(
        role: TlsRole,
        keystream_mpc: Keystream<Aes128>,
        keystream_zk: Keystream<Aes128>,
        ghash: GhashCompute,
    ) -> Self {
        Self {
            role,
            key: None,
            iv: None,
            keystream_mpc,
            keystream_zk,
            ghash,
        }
    }

    /// Sets key and iv if available, for local decryption of the leader.
    ///
    /// # Arguments
    ///
    /// * `key` - Some key for the leader, None for follower.
    /// * `iv` - Some iv for the leader, None for follower.
    pub(crate) fn set_key_and_iv(&mut self, key: Option<Vec<u8>>, iv: Option<Vec<u8>>) {
        self.key = key;
        self.iv = iv;
    }

    /// Decrypts a ciphertext.
    ///
    /// Returns the plaintext and plaintext refs. Also verifies tags.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `ctx` - The context for IO.
    /// * `requests` - Decryption requests.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn decrypt<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        requests: Vec<DecryptRequest>,
    ) -> Result<(Option<Vec<PlainMessage>>, Vec<Vector<U8>>), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
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
            let j0 = self.keystream_mpc.j0(vm, explicit_nonce)?;
            let j0 = Decode::new(vm, self.role, transmute(j0))?;
            let j0 = j0.shared(vm)?;

            let keystream = self.keystream_mpc.chunk_sufficient(ciphertext.len())?;
            let cipher_ref: Vector<U8> = vm.alloc_vec(ciphertext.len()).map_err(MpcTlsError::vm)?;
            vm.mark_public(cipher_ref).map_err(MpcTlsError::vm)?;

            let cipher_out = keystream.apply(vm, cipher_ref).map_err(MpcTlsError::vm)?;
            let plaintext_ref = cipher_out
                .assign(
                    vm,
                    explicit_nonce,
                    START_COUNTER,
                    Input::Message(ciphertext.clone()),
                )
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

        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        let messages = decrypt.compute(ctx).await?;

        Ok((messages, plaintext_refs))
    }

    /// Decrypts a ciphertext locally.
    ///
    /// Returns plain messages, if available, and plaintext refs.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `requests` - Decryption requests.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn decrypt_local<V, Ctx>(
        &mut self,
        vm: &mut V,
        requests: Vec<DecryptRequest>,
    ) -> Result<(Option<Vec<PlainMessage>>, Vec<Vector<U8>>), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        // Tag verification was already done, so we only decrypt locally.
        let len = requests.len();
        let mut plaintexts = match self.role {
            TlsRole::Leader => Some(Vec::with_capacity(len)),
            TlsRole::Follower => None,
        };

        let mut plaintext_refs = Vec::with_capacity(len);

        for DecryptRequest {
            ciphertext,
            typ,
            version,
            explicit_nonce,
            ..
        } in requests
        {
            let plaintext = match self.role {
                TlsRole::Leader => {
                    let key = self.key.as_ref().expect("Leader should have key");
                    let iv = self.iv.as_ref().expect("Leaders hould have iv");
                    let plaintext = Self::aes_ctr_local(
                        &key,
                        &iv,
                        START_COUNTER as usize,
                        &explicit_nonce,
                        &ciphertext,
                    )?;
                    Some(plaintext)
                }
                TlsRole::Follower => None,
            };
            let plaintext_ref: Vector<U8> =
                vm.alloc_vec(ciphertext.len()).map_err(MpcTlsError::vm)?;

            match self.role {
                TlsRole::Leader => vm.mark_private(plaintext_ref).map_err(MpcTlsError::vm)?,
                TlsRole::Follower => vm.mark_blind(plaintext_ref).map_err(MpcTlsError::vm)?,
            }

            if let Some(plaintext) = plaintext {
                vm.assign(plaintext_ref, plaintext.clone())
                    .map_err(MpcTlsError::vm)?;

                match plaintexts.as_mut() {
                    Some(plaintexts) => {
                        let plaintext = PlainMessage {
                            typ,
                            version,
                            payload: Payload(plaintext),
                        };

                        plaintexts.push(plaintext);
                    }
                    None => (),
                }
                vm.commit(plaintext_ref).map_err(MpcTlsError::vm)?;
            }
            plaintext_refs.push(plaintext_ref);
        }

        Ok((plaintexts, plaintext_refs))
    }

    /// Verifies tags of ciphertexts.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `ctx` - The context for IO.
    /// * `requests` - Decryption requests.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn verify_tags<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        requests: Vec<DecryptRequest>,
    ) -> Result<(), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let len = requests.len();

        let mut j0s = Vec::with_capacity(len);
        let mut ciphertexts = Vec::with_capacity(len);
        let mut aads = Vec::with_capacity(len);
        let mut purported_tags = Vec::with_capacity(len);

        for DecryptRequest {
            ciphertext,
            explicit_nonce,
            aad,
            purported_tag,
            ..
        } in requests
        {
            let j0 = self.keystream_mpc.j0(vm, explicit_nonce)?;
            let j0 = Decode::new(vm, self.role, transmute(j0))?;
            let j0 = j0.shared(vm)?;

            j0s.push(j0);
            ciphertexts.push(ciphertext);
            aads.push(aad);
            purported_tags.push(purported_tag);
        }

        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        let mut future: FuturesOrdered<_> = j0s.into_iter().map(|j0| j0.decode()).collect();
        let mut j0s = Vec::with_capacity(len);
        while let Some(j0) = future.next().await {
            j0s.push(j0?);
        }

        let tags = TagComputer::new(j0s, ciphertexts, aads).compute(&self.ghash)?;
        tags.verify(ctx, self.role, TagBatch::new(purported_tags))
            .await?;

        Ok(())
    }

    /// Re-encrypt plaintexts to ciphertexts.
    ///
    /// # Arguments
    ///
    /// * `vm` - A virtual machine for 2PC.
    /// * `ctx` - The context for IO.
    /// * `messages` - The plaintext messages, if available.
    /// * `plaintext_refs` - The plaintext references.
    /// * `explicit_nonces` - The TLS explicit nonces.
    #[instrument(level = "trace", skip_all, err)]
    pub(crate) async fn prove<V, Ctx>(
        &mut self,
        vm: &mut V,
        ctx: &mut Ctx,
        messages: Option<Vec<PlainMessage>>,
        plaintext_refs: Vec<Vector<U8>>,
        explicit_nonces: Vec<[u8; 8]>,
    ) -> Result<Vec<Vec<u8>>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let len = plaintext_refs.len();

        let mut future = FuturesOrdered::new();
        for k in 0..len {
            let explicit_nonce = explicit_nonces[k];
            let plaintext_ref = plaintext_refs[k];
            let plaintext_len = plaintext_ref.len();

            let keystream = self.keystream_zk.chunk_sufficient(plaintext_len)?;
            let plaintext = match messages {
                Some(ref plaintext) => Input::Message(plaintext[k].payload.0.clone()),
                None => Input::Length(plaintext_len),
            };

            let cipher_out = keystream
                .apply(vm, plaintext_ref)
                .map_err(MpcTlsError::vm)?;
            let cipher_ref = cipher_out
                .assign(vm, explicit_nonce, START_COUNTER, plaintext)
                .map_err(MpcTlsError::vm)?;

            let ciphertext = vm.decode(cipher_ref).map_err(MpcTlsError::decode)?;
            future.push_back(ciphertext);
        }
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;
        vm.execute(ctx).await.map_err(MpcTlsError::vm)?;
        vm.flush(ctx).await.map_err(MpcTlsError::vm)?;

        let mut ciphertexts = Vec::with_capacity(len);

        while let Some(ciphertext) = future.next().await {
            ciphertexts.push(ciphertext?);
        }

        Ok(ciphertexts)
    }

    fn aes_ctr_local(
        key: &[u8],
        iv: &[u8],
        start_ctr: usize,
        explicit_nonce: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, MpcTlsError> {
        use aes::Aes128;
        use cipher_crate::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use ctr::Ctr32BE;

        const BLOCK_LEN: usize = 16;

        let key: &[u8; 16] = key
            .try_into()
            .map_err(|_| MpcTlsError::decrypt("key has wrong length for local decrypt"))?;
        let iv: &[u8; 4] = iv
            .try_into()
            .map_err(|_| MpcTlsError::decrypt("iv has wrong length for local decrypt"))?;
        let explicit_nonce: &[u8; 8] = explicit_nonce
            .try_into()
            .map_err(|_| MpcTlsError::decrypt("nonce has wrong length for local decrypt"))?;

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(iv);
        full_iv[4..12].copy_from_slice(explicit_nonce);
        let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
        let mut buf = msg.to_vec();

        cipher
            .try_seek(start_ctr * BLOCK_LEN)
            .expect("start counter is less than keystream length");
        cipher.apply_keystream(&mut buf);

        Ok(buf)
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
    fn new(role: TlsRole, ghash: GhashCompute, cap: usize) -> Self {
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
    fn push(
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
    fn len(&self) -> usize {
        self.ciphertexts.len()
    }

    /// Computes the plaintext and verifies tags.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context for IO.
    async fn compute<Ctx>(self, ctx: &mut Ctx) -> Result<Option<Vec<PlainMessage>>, MpcTlsError>
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

        let output: Option<Vec<PlainMessage>> = self
            .typs
            .into_iter()
            .zip(self.versions)
            .zip(plaintexts)
            .map(|((typ, version), plaintext)| {
                plaintext.map(|c| PlainMessage {
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

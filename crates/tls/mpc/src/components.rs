use crate::{
    record_layer::{
        aead::ghash::{Ghash, GhashConfig},
        Decrypter, Encrypter,
    },
    TlsRole,
};
use cipher::aes::MpcAes;
use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role as PrfRole};
use key_exchange::{KeyExchange, KeyExchangeConfig, MpcKeyExchange, Role as KeRole};
use mpz_fields::{gf2_128::Gf2_128, p256::P256};
use mpz_memory_core::{binary::Binary, Memory, View};
use mpz_ole::{ROLEReceiver, ROLESender};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender, ShareConvert};
use mpz_vm_core::Vm;

/// Builds the components for MPC-TLS leader.
pub fn build_leader<V, RSP, RRP, RSGF>(
    rs_p: RSP,
    rr_p: RRP,
    rs_gf0: RSGF,
    rs_gf1: RSGF,
) -> (
    impl KeyExchange<V>,
    impl Prf<V>,
    MpcAes,
    Encrypter<impl ShareConvert<Gf2_128>>,
    Decrypter<impl ShareConvert<Gf2_128>>,
)
where
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Send,
    RSP: ROLESender<P256> + Send,
    RRP: ROLEReceiver<P256> + Send,
    RSGF: ROLESender<Gf2_128> + Send,
{
    let role = TlsRole::Leader;

    let ke = MpcKeyExchange::new(
        KeyExchangeConfig::builder()
            .role(KeRole::Leader)
            .build()
            .unwrap(),
        ShareConversionSender::new(rs_p),
        ShareConversionReceiver::new(rr_p),
    );

    let prf = MpcPrf::new(
        PrfConfig::builder()
            .role(match role {
                TlsRole::Leader => PrfRole::Leader,
                TlsRole::Follower => PrfRole::Follower,
            })
            .build()
            .unwrap(),
    );

    let cipher = MpcAes::default();

    let ghash_encrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionSender::new(rs_gf0),
    );
    let encrypter = Encrypter::new(role, ghash_encrypt);

    let ghash_decrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionSender::new(rs_gf1),
    );
    let decrypter = Decrypter::new(role, ghash_decrypt);

    (ke, prf, cipher, encrypter, decrypter)
}

/// Builds the components for MPC-TLS follower.
pub fn build_follower<V, RSP, RRP, RRGF>(
    rs_p: RSP,
    rr_p: RRP,
    rr_gf0: RRGF,
    rr_gf1: RRGF,
) -> (
    impl KeyExchange<V>,
    impl Prf<V>,
    MpcAes,
    Ghash<impl ShareConvert<Gf2_128>>,
    Ghash<impl ShareConvert<Gf2_128>>,
)
where
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Send,
    RSP: ROLESender<P256> + Send,
    RRP: ROLEReceiver<P256> + Send,
    RRGF: ROLEReceiver<Gf2_128> + Send,
{
    let role = TlsRole::Follower;

    let ke = MpcKeyExchange::new(
        KeyExchangeConfig::builder()
            .role(KeRole::Follower)
            .build()
            .unwrap(),
        ShareConversionReceiver::new(rr_p),
        ShareConversionSender::new(rs_p),
    );

    let prf = MpcPrf::new(
        PrfConfig::builder()
            .role(match role {
                TlsRole::Leader => PrfRole::Leader,
                TlsRole::Follower => PrfRole::Follower,
            })
            .build()
            .unwrap(),
    );

    let cipher = MpcAes::default();

    let ghash_encrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionReceiver::new(rr_gf0),
    );
    let ghash_decrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionReceiver::new(rr_gf1),
    );

    (ke, prf, cipher, ghash_encrypt, ghash_decrypt)
}

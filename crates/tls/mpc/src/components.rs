//! Helper code for dependency injection.
//!
//! Builds components needed by [`crate::leader::MpcTlsLeader`] and
//! [`crate::follower::MpcTlsFollower`];

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
use mpz_common::{Context, Flush};
use mpz_fields::{gf2_128::Gf2_128, p256::P256};
use mpz_memory_core::{binary::Binary, Memory, View};
use mpz_ole::{ROLEReceiver, ROLESender};
use mpz_share_conversion::{
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionReceiver,
    ShareConversionSender, ShareConvert,
};
use mpz_vm_core::Vm;

/// Builds the components for MPC-TLS leader.
///
/// # Arguments
///
/// * `rs_p` - ROLE sender for P256 field elements.
/// * `rr_p` - ROLE receiver for P256 field elements.
/// * `rs_gf0` - ROLE sender for Gf2_128 field elements.
/// * `rs_gf1` - ROLE sender for Gf2_128 field elements.
#[allow(clippy::type_complexity)]
#[allow(clippy::implied_bounds_in_impls)]
pub fn build_leader<Ctx, V, RSP, RRP, RSGF>(
    _: Ctx,
    rs_p: RSP,
    rr_p: RRP,
    rs_gf0: RSGF,
    rs_gf1: RSGF,
) -> (
    impl KeyExchange<V> + Flush<Ctx> + Send,
    impl Prf<V> + Send,
    MpcAes,
    Encrypter<
        impl ShareConvert<Gf2_128>
            + AdditiveToMultiplicative<Gf2_128, Future: Send>
            + MultiplicativeToAdditive<Gf2_128, Future: Send>
            + Flush<Ctx>,
    >,
    Decrypter<
        impl ShareConvert<Gf2_128>
            + AdditiveToMultiplicative<Gf2_128, Future: Send>
            + MultiplicativeToAdditive<Gf2_128, Future: Send>
            + Flush<Ctx>,
    >,
)
where
    V: Vm<Binary> + View<Binary> + Memory<Binary> + Send,
    RSP: ROLESender<P256> + Flush<Ctx> + Send,
    RRP: ROLEReceiver<P256> + Flush<Ctx> + Send,
    RSGF: ROLESender<Gf2_128> + Flush<Ctx> + Send,
    Ctx: Context,
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

    let prf = MpcPrf::new(PrfConfig::builder().role(PrfRole::Leader).build().unwrap());

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
///
/// # Arguments
///
/// * `rs_p` - ROLE sender for P256 field elements.
/// * `rr_p` - ROLE receiver for P256 field elements.
/// * `rr_gf0` - ROLE receiver for Gf2_128 field elements.
/// * `rr_gf1` - ROLE receiver for Gf2_128 field elements.
pub fn build_follower<V, RSP, RRP, RRGF>(
    rs_p: RSP,
    rr_p: RRP,
    rr_gf0: RRGF,
    rr_gf1: RRGF,
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
            .role(PrfRole::Follower)
            .build()
            .unwrap(),
    );

    let cipher = MpcAes::default();

    let ghash_encrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionReceiver::new(rr_gf0),
    );
    let encrypter = Encrypter::new(role, ghash_encrypt);

    let ghash_decrypt = Ghash::new(
        GhashConfig::builder().build().unwrap(),
        ShareConversionReceiver::new(rr_gf1),
    );
    let decrypter = Decrypter::new(role, ghash_decrypt);

    (ke, prf, cipher, encrypter, decrypter)
}

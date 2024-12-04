use std::{sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt};
use mpz_common::{
    executor::mt::{MTConfig, MTExecutor},
    Context, Flush,
};
use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, p256::P256, Field};
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::{binary::Binary, correlated::Delta, View};
use mpz_ole::{ideal::IdealROLE, ROLEReceiver, ROLESender};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Execute, Vm};
use rand::{rngs::StdRng, SeedableRng};
use serio::{Deserialize, Serialize, StreamExt};
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_mpc::{
    build_follower, build_leader, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig,
    MpcTlsLeader, MpcTlsLeaderConfig,
};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{
    test_utils::{test_framed_mux, TestFramedMux},
    FramedUidMux,
};

fn create_vm<Ctx>() -> (
    impl Vm<Binary> + View<Binary> + Execute<Ctx>,
    impl Vm<Binary> + View<Binary> + Execute<Ctx>,
)
where
    Ctx: Context + 'static,
{
    let mut rng = StdRng::seed_from_u64(0);
    let block = Block::random(&mut rng);
    let (sender, receiver) = ideal_cot(block);

    let delta = Delta::new(block);
    let gen = Generator::new(sender, [0u8; 16], delta);
    let ev = Evaluator::new(receiver);

    (gen, ev)
}

fn create_role<Ctx, F>() -> (
    impl ROLESender<F> + Flush<Ctx> + Send,
    impl ROLEReceiver<F> + Flush<Ctx> + Send,
)
where
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    let mut rng = StdRng::seed_from_u64(0);
    let block = Block::random(&mut rng);
    let role = IdealROLE::new(block);

    let sender = role.clone();
    let receiver = role;

    (sender, receiver)
}

async fn leader<Ctx, RSGF>(
    rs_p_0: impl ROLESender<P256> + Flush<Ctx> + Send + 'static,
    rr_p_1: impl ROLEReceiver<P256> + Flush<Ctx> + Send + 'static,
    rs_gf_0: RSGF,
    rs_gf_1: RSGF,
    mux: TestFramedMux,
    ctx: Ctx,
    vm: impl Vm<Binary> + View<Binary> + Execute<Ctx> + Send + 'static,
) where
    Ctx: Context + Send + 'static,
    RSGF: ROLESender<Gf2_128> + Flush<Ctx> + Send + 'static,
{
    let (ke, prf, cipher, encrypter, decrypter) =
        build_leader::<Ctx, _, _, _, _>(rs_p_0, rr_p_1, rs_gf_0, rs_gf_1);

    let common_config = MpcTlsCommonConfig::builder().build().unwrap();
    let mut leader = MpcTlsLeader::<_, _, _, _, Ctx, _>::new(
        MpcTlsLeaderConfig::builder()
            .common(common_config)
            .defer_decryption_from_start(false)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        cipher,
        encrypter,
        decrypter,
        ctx,
        vm,
    );

    leader.setup().await.unwrap();

    let (leader_ctrl, leader_fut) = leader.run();
    tokio::spawn(async { leader_fut.await.unwrap() });

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add(&Certificate(CA_CERT_DER.to_vec())).unwrap();
    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = SERVER_DOMAIN.try_into().unwrap();

    let client = tls_client::ClientConnection::new(
        Arc::new(config),
        Box::new(leader_ctrl.clone()),
        server_name,
    )
    .unwrap();

    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (mut conn, conn_fut) = bind_client(client_socket.compat(), client);

    tokio::spawn(async { conn_fut.await.unwrap() });

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: keep-alive\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 48];
    conn.read_exact(&mut buf).await.unwrap();

    println!("{}", String::from_utf8_lossy(&buf));

    leader_ctrl.defer_decryption().await.unwrap();

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    // Wait for the server to reply.
    tokio::time::sleep(Duration::from_millis(100)).await;

    leader_ctrl.commit().await.unwrap();

    let mut buf = vec![0u8; 1024];
    conn.read_to_end(&mut buf).await.unwrap();

    leader_ctrl.close_connection().await.unwrap();
    conn.close().await.unwrap();

    //vm.finalize().await.unwrap();
}

async fn follower<Ctx, RRGF>(
    rs_p_1: impl ROLESender<P256> + Flush<Ctx> + Send + 'static,
    rr_p_0: impl ROLEReceiver<P256> + Flush<Ctx> + Send + 'static,
    rr_gf_0: RRGF,
    rr_gf_1: RRGF,
    mux: TestFramedMux,
    ctx: Ctx,
    vm: impl Vm<Binary> + View<Binary> + Execute<Ctx> + Send + 'static,
) where
    RRGF: ROLEReceiver<Gf2_128> + Flush<Ctx> + Send + 'static,
    Ctx: Context + Send + 'static,
{
    let (ke, prf, cipher, encrypter, decrypter) =
        build_follower::<Ctx, _, _, _, _>(rs_p_1, rr_p_0, rr_gf_0, rr_gf_1);

    let common_config = MpcTlsCommonConfig::builder().build().unwrap();
    let mut follower = MpcTlsFollower::<_, _, _, _, Ctx, _>::new(
        MpcTlsFollowerConfig::builder()
            .common(common_config)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        cipher,
        encrypter,
        decrypter,
        ctx,
        vm,
    );

    follower.setup().await.unwrap();

    let (_, fut) = follower.run();
    fut.await.unwrap();

    // vm.finalize().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let (leader_mux, follower_mux) = test_framed_mux(8);
    let mt_config = MTConfig::default();

    let (ctx_leader, ctx_follower) = futures::try_join!(
        MTExecutor::new(leader_mux.clone(), mt_config.clone()).new_thread(),
        MTExecutor::new(follower_mux.clone(), mt_config).new_thread()
    )
    .unwrap();

    let (gen, ev) = create_vm();

    let (p256_sender_0, p256_receiver_0) = create_role::<_, P256>();
    let (p256_sender_1, p256_receiver_1) = create_role::<_, P256>();
    let (gf2_sender_0, gf2_receiver_0) = create_role::<_, Gf2_128>();
    let (gf2_sender_1, gf2_receiver_1) = create_role::<_, Gf2_128>();

    tokio::join!(
        leader(
            p256_sender_0,
            p256_receiver_1,
            gf2_sender_0,
            gf2_sender_1,
            leader_mux,
            ctx_leader,
            gen
        ),
        follower(
            p256_sender_1,
            p256_receiver_0,
            gf2_receiver_0,
            gf2_receiver_1,
            follower_mux,
            ctx_follower,
            ev
        ),
    );
}

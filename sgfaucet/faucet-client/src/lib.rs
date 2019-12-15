use faucet_proto::proto::faucet::SgFaucetClient;
use grpcio::{ChannelBuilder, Environment};
use std::sync::Arc;

fn _make_clients(
    env: Arc<Environment>,
    host: &str,
    port: u16,
    client_type: &str,
    max_receive_len: Option<i32>,
) -> SgFaucetClient {
    let mut builder = ChannelBuilder::new(env.clone())
        .primary_user_agent(format!("grpc/faucet-{}", client_type).as_str());
    if let Some(m) = max_receive_len {
        builder = builder.max_receive_message_len(m);
    }
    let channel = builder.connect(&format!("{}:{}", host, port));
    SgFaucetClient::new(channel)
}

#[test]
fn test_faucet() {
    use faucet_proto::proto::faucet::FaucetRequest as FaucetRequestProto;
    use faucet_proto::FaucetRequest;
    use faucet_service::{load_faucet_conf, FaucetNode};
    use grpcio::EnvBuilder;
    use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use libra_crypto::test_utils::KeyPair;
    use libra_crypto::traits::Uniform;
    use libra_types::account_address::AccountAddress;
    use rand::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::fs;
    use std::path::PathBuf;
    use std::thread::sleep;
    use std::time::Duration;

    ::libra_logger::init_for_e2e_testing();
    //1. chain
    let faucet_path = "/tmp/faucet";
    let (mut node_config, _logger, _handler) = sgchain::main_node::run_node(None, false, false);
    //1.1 save chain node config
    node_config.consensus.save_key(faucet_path);

    //2. faucet server
    //2.1 create FaucetConf
    let current_dir = PathBuf::from("./");
    let mut faucet_conf = load_faucet_conf(format!(
        "{}/{}",
        fs::canonicalize(&current_dir)
            .expect("path err.")
            .to_str()
            .expect("str err."),
        "../faucet-service"
    ));
    faucet_conf.set_key_file(faucet_path.to_string());
    let (host, port) = faucet_conf.server();
    //2.2 start server
    let _faucet_service = FaucetNode::run(faucet_conf);

    //3. faucet client
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-coord-").build());
    let faucet_client = _make_clients(client_env, host.as_str(), port, "read", None);

    //4. address
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);
    let address = AccountAddress::from_public_key(&account_keypair.public_key);

    sleep(Duration::from_secs(60 * 2));
    //5. faucet
    let req = FaucetRequest::new(address, 10);
    let req_proto = FaucetRequestProto::from(req);
    let _resp = faucet_client.faucet(&req_proto);
    sleep(Duration::from_secs(10));
    let _resp = faucet_client.faucet(&req_proto);
    sleep(Duration::from_secs(20));
    drop(_handler);
}

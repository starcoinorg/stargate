use network::{build_network_service, convert_account_address_to_peer_id, NetworkService};
use std::io::Result;

use rand::prelude::*;

use crate::node::Node;
use core::borrow::Borrow;
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::{CryptoHasher, TestOnlyHasher},
    test_utils::KeyPair,
    traits::SigningKey,
    Uniform,
};
use futures_01::future::Future as Future01;
use logger::prelude::*;
use proto_conv::{FromProto, FromProtoBytes, IntoProto, IntoProtoBytes};
use sg_config::config::NetworkConfig;
use sgchain::star_chain_client::{faucet_sync, ChainClient, MockChainClient};
use sgwallet::wallet::*;
use star_types::message::*;
use std::{
    convert::identity,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::{Runtime, TaskExecutor};
use types::{account_address::AccountAddress, account_config::coin_struct_tag};

pub fn gen_node(
    executor: TaskExecutor,
    config: &NetworkConfig,
    client: Arc<MockChainClient>,
) -> (
    Node<MockChainClient>,
    AccountAddress,
    KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
) {
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts()); //SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    faucet_sync(client.as_ref().clone(), account_address, amount).unwrap();
    let mut wallet = Wallet::new_with_client(account_address, keypair.clone(), client).unwrap();
    let (network, tx, rx, close_tx) = build_network_service(config, keypair.clone());
    let identify = network.identify();
    thread::sleep(Duration::from_millis(1000));
    (
        Node::new(
            executor.clone(),
            wallet,
            keypair.clone(),
            network,
            tx,
            rx,
            close_tx,
        ),
        account_address,
        keypair,
    )
}

pub fn create_node_network_config(addr: String, seeds: Vec<String>) -> NetworkConfig {
    return NetworkConfig {
        listen: addr,
        seeds,
    };
}

fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    ;
    since_the_epoch.as_millis() as u64
}

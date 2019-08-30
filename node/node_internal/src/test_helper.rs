use network::{build_network_service, NetworkService, convert_account_address_to_peer_id};
use std::io::Result;

use rand::prelude::*;

use chain_client::{ChainClient, RpcChainClient};
use mock_chain_client::MockChainClient;
use crypto::test_utils::KeyPair;
use crypto::Uniform;
use types::account_address::AccountAddress;
use star_types::message::{*};
use sgwallet::wallet::*;
use crypto::hash::{CryptoHasher, TestOnlyHasher};
use proto_conv::{IntoProtoBytes, FromProto, FromProtoBytes, IntoProto};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::traits::SigningKey;
use std::sync::{Arc, Mutex};
use futures_01::future::Future as Future01;
use std::{
    time::{SystemTime, UNIX_EPOCH, Duration},
    thread,
};
use types::account_config::coin_struct_tag;
use logger::prelude::*;
use sg_config::config::NetworkConfig;
use tokio::runtime::{Runtime, TaskExecutor};
use crate::node::Node;
use std::convert::identity;

pub fn gen_node(executor: TaskExecutor, config: &NetworkConfig, client: Arc<MockChainClient>) -> (Node<MockChainClient>, AccountAddress, KeyPair<Ed25519PrivateKey, Ed25519PublicKey>) {
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts());//SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    client.faucet(account_address, amount).unwrap();
    thread::sleep(Duration::from_millis(1000));
    let mut wallet = Wallet::new_with_client(executor.clone(),account_address, keypair.clone(), client).unwrap();
    let (network, tx, rx) = build_network_service(config, keypair.clone(),executor.clone());
    (Node::new(executor.clone(), wallet, keypair.clone(), network, tx, rx), account_address, keypair)
}

pub fn create_node_network_config(addr: String, seeds: Vec<String>) -> NetworkConfig {
    return NetworkConfig {
        listen: addr,
        seeds,
    };
}

fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    ;
    since_the_epoch.as_millis() as u64
}

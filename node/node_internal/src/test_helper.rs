// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use network::build_network_service;
use rand::prelude::*;

use crate::node::Node;
use anyhow::Error;
use libra_crypto::{test_utils::KeyPair, Uniform};
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use router::Router;
use sg_config::config::NetworkConfig;
use sgchain::star_chain_client::{faucet_sync, MockChainClient};
use sgwallet::wallet::*;
use std::{
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::{Handle, Runtime};

pub fn gen_node(
    rt: &mut Runtime,
    executor: Handle,
    config: &NetworkConfig,
    client: Arc<MockChainClient>,
    auto_approve: bool,
) -> (Node, AccountAddress) {
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts()); //SeedableRng::from_seed([0; 32]);
    let keypair = Arc::new(KeyPair::generate_for_testing(&mut rng));
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    faucet_sync(client.as_ref().clone(), account_address, amount).unwrap();
    let store_path = TempPath::new();

    let mut router = Router::new(client.clone(), executor.clone());
    router.start().unwrap();

    let mut wallet =
        Wallet::new_with_client(account_address, keypair.clone(), client, store_path.path())
            .unwrap();
    wallet.start(&executor).unwrap();

    let f = async {
        let enabled: bool = wallet.is_channel_feature_enabled().await?;
        if !enabled {
            wallet.enable_channel().await?;
        }
        Ok::<_, Error>(())
    };
    rt.block_on(f).unwrap();

    let (network, tx, rx, close_tx) = build_network_service(config, keypair.clone());
    let _identify = network.identify();

    thread::sleep(Duration::from_millis(1000));
    (
        Node::new(
            executor.clone(),
            wallet,
            network,
            tx,
            rx,
            close_tx,
            auto_approve,
            5000,
            router,
        ),
        account_address,
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
    since_the_epoch.as_millis() as u64
}

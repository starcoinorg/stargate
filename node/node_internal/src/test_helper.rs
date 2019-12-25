// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use network::build_network_service;
use rand::prelude::*;

use crate::get_unix_ts;
use crate::node::Node;
use anyhow::Error;
use libra_crypto::{test_utils::KeyPair, Uniform};
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use router::TableRouter;
use sg_config::config::NetworkConfig;
use sgchain::star_chain_client::{faucet_sync, MockChainClient};
use sgwallet::wallet::*;
use std::{sync::Arc, thread, time::Duration};
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

    let mut wallet = Wallet::new_with_client(
        account_address,
        keypair.clone(),
        client.clone(),
        store_path.path(),
    )
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

    let wallet = Arc::new(wallet);

    let (tx, rx) = futures::channel::mpsc::unbounded();
    let mut router = TableRouter::new(client, executor.clone(), wallet.clone(), tx, rx);
    router.start().unwrap();

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

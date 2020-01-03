// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use network::build_network_service;
use rand::prelude::*;

use crate::node::Node;
use anyhow::Result;
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use libra_crypto::{test_utils::KeyPair, Uniform};
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use router::TableRouter;
use sg_config::config::NetworkConfig;
use sgchain::star_chain_client::{ChainClient, MockChainClient};
use sgwallet::wallet::*;
use stats::Stats;
use std::{sync::Arc, thread, time::Duration};
use tokio::runtime::Handle;

pub async fn setup_wallet(client: Arc<dyn ChainClient>, init_balance: u64) -> Result<WalletHandle> {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> =
        Arc::new(KeyPair::generate_for_testing(&mut rng0));
    let account = AccountAddress::from_public_key(&account_keypair.public_key);

    client.faucet(account, init_balance).await?;
    // enable channel for wallet
    let wallet =
        Wallet::new_with_client(account, account_keypair, client.clone(), TempPath::new())?;
    let handle = wallet.start().await?;
    let gas_used = handle.enable_channel().await?;
    handle.get_chain_client().faucet(account, gas_used).await?;

    let wallet_balance = handle.balance()?;
    assert_eq!(
        init_balance, wallet_balance,
        "not equal, balance: {:?}",
        wallet_balance
    );
    Ok(handle)
}

pub fn gen_node(
    wallet: WalletHandle,
    executor: Handle,
    config: &NetworkConfig,
    client: Arc<MockChainClient>,
    auto_approve: bool,
) -> (Node, AccountAddress) {
    let wallet = Arc::new(wallet);
    let account_address = wallet.account();
    let (rtx1, rrx1) = futures::channel::mpsc::unbounded();
    let (rtx2, rrx2) = futures::channel::mpsc::unbounded();

    let stats_mgr = Stats::new(executor.clone());
    let mut router = TableRouter::new(
        client,
        executor.clone(),
        wallet.clone(),
        rtx1,
        rrx2,
        Arc::new(stats_mgr),
    );
    router.start().unwrap();

    let (network, tx, rx, close_tx) = build_network_service(config, wallet.keypair());
    let _identify = network.identify();

    thread::sleep(Duration::from_millis(1000));
    (
        Node::new(
            executor.clone(),
            wallet,
            network,
            tx,
            rx,
            rtx2,
            rrx1,
            close_tx,
            auto_approve,
            10000,
            Box::new(router),
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

// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::wallet_test_helper::setup_wallet;
use failure::prelude::*;
use sgchain::star_chain_client::ChainClient;
use sgwallet::wallet::Wallet;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::sleep,
};
use tokio::runtime::Runtime;

pub fn with_wallet<T, F>(chain_client: Arc<dyn ChainClient>, f: F) -> Result<T>
where
    F: Fn(&Runtime, Arc<Wallet>, Arc<Wallet>) -> Result<T>,
{
    let init_amount = 10_000_000;
    let rt = Runtime::new()?;
    let mut sender_wallet = setup_wallet(chain_client.clone(), init_amount)?;
    let mut receiver_wallet = setup_wallet(chain_client.clone(), init_amount)?;
    sender_wallet.start(rt.executor().clone())?;
    receiver_wallet.start(rt.executor().clone())?;
    let sender_wallet = Arc::new(sender_wallet);
    let receiver_wallet = Arc::new(receiver_wallet);

    let res = f(&rt, sender_wallet.clone(), receiver_wallet.clone());
    rt.block_on(sender_wallet.stop())?;
    rt.block_on(receiver_wallet.stop())?;
    rt.shutdown_on_idle();
    res
}

pub async fn send_payment(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    amount: u64,
    hash_lock: Vec<u8>,
    timeout: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    let req = sender_wallet
        .send_payment(receiver_wallet.account(), amount, hash_lock, timeout)
        .await?;
    let resp = receiver_wallet.verify_txn(sender, &req).await?;
    let resp = if let Some(t) = resp {
        t
    } else {
        receiver_wallet
            .approve_txn(sender, req.request_id())
            .await?
    };
    let _ = sender_wallet.verify_txn_response(receiver, &resp).await?;
    let sender_gas = sender_wallet.apply_txn(receiver, &resp).await?;
    let _receiver_gas = receiver_wallet.apply_txn(sender, &resp).await?;
    Ok(sender_gas)
}

pub async fn receive_payment(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    preimage: Vec<u8>,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    let req = sender_wallet
        .receive_payment(receiver_wallet.account(), preimage)
        .await?;
    let resp = receiver_wallet.verify_txn(sender, &req).await?;
    let resp = if let Some(t) = resp {
        t
    } else {
        receiver_wallet
            .approve_txn(sender, req.request_id())
            .await?
    };
    let _ = sender_wallet.verify_txn_response(receiver, &resp).await?;
    let sender_gas = sender_wallet.apply_txn(receiver, &resp).await?;
    let _receiver_gas = receiver_wallet.apply_txn(sender, &resp).await?;
    Ok(sender_gas)
}

pub async fn open_channel(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    sender_amount: u64,
    receiver_amount: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    let req = sender_wallet
        .open(receiver_wallet.account(), sender_amount, receiver_amount)
        .await?;
    let resp = receiver_wallet.verify_txn(sender, &req).await?;
    let resp = if let Some(t) = resp {
        t
    } else {
        receiver_wallet
            .approve_txn(sender, req.request_id())
            .await?
    };
    let _ = sender_wallet.verify_txn_response(receiver, &resp).await?;
    let sender_gas = sender_wallet.apply_txn(receiver, &resp).await?;
    let _receiver_gas = receiver_wallet.apply_txn(sender, &resp).await?;
    Ok(sender_gas)
}

// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use anyhow::Result;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use libra_tools::tempdir::TempPath;
use libra_types::{account_address::AccountAddress, transaction::TransactionArgument};
use rand::prelude::*;
use sgchain::star_chain_client::ChainClient;
use sgwallet::wallet::{Wallet, WalletHandle};
use std::sync::Arc;
use tokio::runtime::Runtime;

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

pub fn with_wallet<T, F>(chain_client: Arc<dyn ChainClient>, f: F) -> Result<T>
where
    F: Fn(&mut Runtime, Arc<WalletHandle>, Arc<WalletHandle>) -> Result<T>,
{
    let init_amount = 10_000_000;
    let mut rt = Runtime::new()?;

    let sender_wallet = rt.block_on(setup_wallet(chain_client.clone(), init_amount))?;
    let receiver_wallet = rt.block_on(setup_wallet(chain_client.clone(), init_amount))?;
    let sender_wallet = Arc::new(sender_wallet);
    let receiver_wallet = Arc::new(receiver_wallet);

    let res = f(&mut rt, sender_wallet.clone(), receiver_wallet.clone());
    rt.block_on(sender_wallet.stop())?;
    rt.block_on(receiver_wallet.stop())?;
    drop(rt);
    res
}

pub async fn send_payment(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
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
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
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
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
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
pub async fn deposit(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
    sender_deposit_amount: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();

    let deposit_txn = sender_wallet
        .deposit(receiver, sender_deposit_amount)
        .await?;

    debug_assert!(deposit_txn.is_travel_txn(), "open_txn must travel txn");

    let receiver_deposit_txn = receiver_wallet.verify_txn(sender, &deposit_txn).await?;

    let receiver_deposit_txn = match receiver_deposit_txn {
        Some(t) => t,
        None => {
            receiver_wallet
                .approve_txn(sender, deposit_txn.request_id())
                .await?
        }
    };
    sender_wallet
        .verify_txn_response(receiver, &receiver_deposit_txn)
        .await?;
    let sender_gas_used = sender_wallet
        .apply_txn(receiver, &receiver_deposit_txn)
        .await?;
    receiver_wallet
        .apply_txn(sender, &receiver_deposit_txn)
        .await?;
    Ok(sender_gas_used)
}

pub async fn transfer(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
    transfer_amount: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();

    let transfer_txn = sender_wallet.transfer(receiver, transfer_amount).await?;

    debug_assert!(
        !transfer_txn.is_travel_txn(),
        "transfer_txn must not travel txn"
    );
    //debug!("txn:{:#?}", transfer_txn);

    let receiver_transfer_txn = match receiver_wallet.verify_txn(sender, &transfer_txn).await? {
        Some(t) => t,
        None => {
            receiver_wallet
                .approve_txn(sender, transfer_txn.request_id())
                .await?
        }
    };

    // now,receiver apply the txn
    receiver_wallet
        .apply_txn(sender, &receiver_transfer_txn)
        .await?;
    // then sender still pending
    assert!(
        sender_wallet
            .get_pending_txn_request(receiver_wallet.account())
            .await?
            .is_some(),
        "sender should have pending txn"
    );
    // then retry the txn
    let retried_txn = match receiver_wallet.verify_txn(sender, &transfer_txn).await? {
        Some(t) => t,
        None => {
            receiver_wallet
                .approve_txn(sender, transfer_txn.request_id())
                .await?
        }
    };
    assert_eq!(receiver_transfer_txn, retried_txn, "two txn shold be equal");

    sender_wallet
        .verify_txn_response(receiver, &receiver_transfer_txn)
        .await?;
    let sender_gas_used = sender_wallet
        .apply_txn(receiver, &receiver_transfer_txn)
        .await?;
    //    let _ = receiver_wallet
    //        .apply_txn(sender, &receiver_transfer_txn)
    //        .await?;
    Ok(sender_gas_used)
}

pub async fn withdraw(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
    sender_withdraw_amount: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();

    let withdraw_txn = sender_wallet
        .withdraw(receiver, sender_withdraw_amount)
        .await?;

    debug_assert!(withdraw_txn.is_travel_txn(), "withdraw_txn must travel txn");
    //debug!("txn:{:#?}", withdraw_txn);

    let receiver_withdraw_txn = match receiver_wallet.verify_txn(sender, &withdraw_txn).await? {
        Some(t) => t,
        None => {
            receiver_wallet
                .approve_txn(sender, withdraw_txn.request_id())
                .await?
        }
    };

    sender_wallet
        .verify_txn_response(receiver, &receiver_withdraw_txn)
        .await?;
    let sender_gas_used = sender_wallet
        .apply_txn(receiver, &receiver_withdraw_txn)
        .await?;
    receiver_wallet
        .apply_txn(sender, &receiver_withdraw_txn)
        .await?;
    Ok(sender_gas_used)
}

pub async fn execute_script(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
    package_name: &'static str,
    script_name: &'static str,
    args: Vec<TransactionArgument>,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();

    let txn_request = sender_wallet
        .execute_script(receiver, package_name, script_name, args)
        .await?;
    let txn_response = receiver_wallet.verify_txn(sender, &txn_request).await?;
    let txn_response = match txn_response {
        Some(t) => t,
        None => {
            receiver_wallet
                .approve_txn(sender, txn_request.request_id())
                .await?
        }
    };

    sender_wallet
        .verify_txn_response(receiver, &txn_response)
        .await?;
    let sender_future = sender_wallet.apply_txn(receiver, &txn_response);
    let receiver_future = receiver_wallet.apply_txn(sender, &txn_response);

    let gas_used = sender_future.await?;
    receiver_future.await?;
    Ok(gas_used)
}

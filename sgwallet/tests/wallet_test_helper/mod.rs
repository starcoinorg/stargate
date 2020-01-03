// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use super::common;
use anyhow::{bail, Result};
use futures::TryStreamExt;
use libra_logger::prelude::*;
use libra_types::{
    access_path::AccessPath, account_address::AccountAddress, channel::ChannelEvent,
};
use sgchain::{client_state_view::ClientStateView, star_chain_client::ChainClient};
use sgcompiler::{Compiler, StateViewModuleLoader};
use sgtypes::script_package::ChannelScriptPackage;
use sgwallet::{get_channel_events, wallet::WalletHandle, ChannelChangeEvent};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::sleep,
    time::Duration,
};

//fn faucet_sync(client: Arc<dyn ChainClient>, receiver: AccountAddress, amount: u64) -> Result<()> {
//    let rt = Runtime::new().expect("faucet runtime err.");
//    let f = async move { client.faucet(receiver, amount).await };
//    rt.block_on(f)
//}

pub async fn test_channel_event_watcher_async(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
) -> Result<()> {
    let sender_fund_amount = 10000;
    let receiver_fund_amount = 10000;
    let _gas_used = common::open_channel(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        sender_fund_amount,
        receiver_fund_amount,
    )
    .await?;

    let (mut events, _) = sender_wallet.client().get_events(
        AccessPath::new_for_channel_global_event(),
        0,
        true,
        1,
    )?;
    let event = events.pop().expect("get channel global event fail.");
    let channel_event = ChannelEvent::make_from(event.event.event_data())?;
    let expected_address = AccountAddress::channel_address(
        vec![sender_wallet.account(), receiver_wallet.account()].as_slice(),
    );
    assert_eq!(
        channel_event.channel_address(),
        expected_address,
        "event's channel address {} should equals txn channel address: {}",
        channel_event.channel_address(),
        expected_address,
    );

    let chain_client = sender_wallet.get_chain_client();
    let s = get_channel_events(chain_client, 0, 100);
    let mut s = Box::pin(s);
    let open_event = s.try_next().await?;

    let mut balances = match open_event {
        None => bail!("should have channel event"),
        Some((idx, e)) => {
            assert_eq!(0, idx);
            match e {
                ChannelChangeEvent::Opened { balances, .. } => balances,
                _ => bail!("should be channel opened event"),
            }
        }
    };
    match balances.remove(&sender_wallet.account()) {
        Some(b) => assert_eq!(sender_fund_amount, b),
        None => bail!("should contain participant address"),
    };
    match balances.remove(&receiver_wallet.account()) {
        Some(b) => assert_eq!(receiver_fund_amount, b),
        None => bail!("should contain participant address"),
    };
    Ok(())
}

pub async fn test_wallet_async(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
) -> Result<()> {
    let sender_fund_amount: u64 = 0;
    let receiver_fund_amount: u64 = 0;
    let sender_deposit_amount: u64 = 5_000_000;
    //    let receiver_deposit_amount: u64 = 4_000_000;
    let transfer_amount = 1_000_000;
    let sender_withdraw_amount: u64 = 4_000_000;
    //    let _receiver_withdraw_amount: u64 = 5_000_000;

    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    let sender_amount = sender_wallet.balance()?;
    let receiver_amount = receiver_wallet.balance()?;
    debug!("sender_address: {}, balance: {}", sender, sender_amount);
    debug!(
        "receiver_address: {}, balance: {}",
        receiver, receiver_amount
    );
    let mut sender_gas_used = 0;
    let sender_gas = common::open_channel(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        sender_fund_amount,
        receiver_fund_amount,
    )
    .await?;
    sender_gas_used += sender_gas;

    let sender_channel_balance = sender_wallet.channel_balance(receiver).await?;
    assert_eq!(sender_channel_balance, sender_fund_amount);
    let receiver_channel_balance = receiver_wallet.channel_balance(sender).await?;
    assert_eq!(receiver_channel_balance, receiver_fund_amount);
    debug!(
        "after open: sender_channel_balance:{}, receiver_channel_balance:{}",
        sender_channel_balance, receiver_channel_balance
    );
    let channel_seq_number = sender_wallet.channel_sequence_number(receiver).await?;
    assert_eq!(1, channel_seq_number);

    sender_gas_used += common::deposit(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        sender_deposit_amount,
    )
    .await?;
    let sender_channel_balance = sender_wallet.channel_balance(receiver).await?;
    assert_eq!(
        sender_channel_balance,
        sender_fund_amount + sender_deposit_amount
    );

    let receiver_channel_balance = receiver_wallet.channel_balance(sender).await?;
    assert_eq!(receiver_channel_balance, receiver_fund_amount);

    debug!(
        "after deposit: sender_channel_balance:{}, receiver_channel_balance:{}",
        sender_channel_balance, receiver_channel_balance
    );

    sender_gas_used += common::transfer(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        transfer_amount,
    )
    .await?;
    let sender_channel_balance = sender_wallet.channel_balance(receiver).await?;
    assert_eq!(
        sender_channel_balance,
        sender_fund_amount + sender_deposit_amount - transfer_amount
    );

    let receiver_channel_balance = receiver_wallet.channel_balance(sender).await?;
    assert_eq!(
        receiver_channel_balance,
        receiver_fund_amount + transfer_amount
    );

    debug!(
        "after transfer: sender_channel_balance:{}, receiver_channel_balance:{}",
        sender_channel_balance, receiver_channel_balance
    );
    sender_gas_used += common::withdraw(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        sender_withdraw_amount,
    )
    .await?;

    let channel_seq_number = sender_wallet.channel_sequence_number(receiver).await?;
    let txn = sender_wallet
        .get_applied_txn_by_channel_sequence_number(receiver, channel_seq_number - 1)?;
    assert_eq!(sender, txn.proposer());

    let sender_channel_balance = sender_wallet.channel_balance(receiver).await?;
    assert_eq!(
        sender_channel_balance,
        sender_fund_amount + sender_deposit_amount - transfer_amount - sender_withdraw_amount
    );

    let receiver_channel_balance = receiver_wallet.channel_balance(sender).await?;
    assert_eq!(
        receiver_channel_balance,
        receiver_fund_amount + transfer_amount
    );

    debug!(
        "after withdraw: sender_channel_balance:{}, receiver_channel_balance:{}",
        sender_channel_balance, receiver_channel_balance
    );

    let sender_balance = sender_wallet.balance()?;
    let receiver_balance = receiver_wallet.balance()?;

    assert_eq!(
        sender_balance,
        sender_amount - sender_gas_used - sender_fund_amount - sender_deposit_amount
            + sender_withdraw_amount
    );
    assert_eq!(receiver_balance, receiver_amount - receiver_fund_amount);

    drop(sender_wallet);
    drop(receiver_wallet);
    debug!("finish");
    Ok(())
}

fn get_test_case_path(case_name: &str) -> PathBuf {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root.join(format!("test_case/{}", case_name))
}

pub async fn deploy_custom_module_and_script(
    wallet1: Arc<WalletHandle>,
    wallet2: Arc<WalletHandle>,
    test_case: &str,
) -> Result<()> {
    compile_and_deploy_module(wallet1.clone(), test_case).await?;
    // TODO: remove sleep
    sleep(Duration::from_millis(1000));
    let package = compile_package(wallet1.clone(), test_case)?;
    wallet1.install_package(package.clone()).await?;
    wallet2.install_package(package).await?;
    Ok(())
}

async fn compile_and_deploy_module(wallet: Arc<WalletHandle>, test_case: &str) -> Result<()> {
    let path = get_test_case_path(test_case);
    let module_source = std::fs::read_to_string(path.join("module.mvir"))?;

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    let module_byte_code = compiler.compile_module(module_source.as_str())?;

    wallet.deploy_module(module_byte_code).await?;
    Ok(())
}

fn compile_package(wallet: Arc<WalletHandle>, test_case: &str) -> Result<ChannelScriptPackage> {
    let path = get_test_case_path(test_case);

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    compiler.compile_package(path.join("scripts"))
}

pub fn test_deploy_custom_module(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    common::with_wallet(chain_client.clone(), |rt, alice, bob| {
        rt.block_on(async {
            deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_custom_module")
                .await?;
            common::open_channel(alice.clone(), bob.clone(), 100000u64, 100000u64).await?;
            common::execute_script(alice.clone(), bob.clone(), "scripts", "do_nothing", vec![])
                .await?;
            Ok(())
        })
    })?;

    Ok(())
}

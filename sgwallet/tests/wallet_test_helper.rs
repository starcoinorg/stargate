// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;

use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use libra_logger::prelude::*;
use libra_tools::tempdir::TempPath;
use libra_types::access_path::AccessPath;
use libra_types::channel_account::ChannelEvent;
use libra_types::{account_address::AccountAddress, transaction::TransactionArgument};
use rand::prelude::*;
use sgchain::{client_state_view::ClientStateView, star_chain_client::ChainClient};
use sgcompiler::{Compiler, StateViewModuleLoader};
use sgtypes::script_package::ChannelScriptPackage;
use sgwallet::wallet::Wallet;
use std::time::Duration;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::sleep,
};
use tokio::runtime::Runtime;

//fn faucet_sync(client: Arc<dyn ChainClient>, receiver: AccountAddress, amount: u64) -> Result<()> {
//    let rt = Runtime::new().expect("faucet runtime err.");
//    let f = async move { client.faucet(receiver, amount).await };
//    rt.block_on(f)
//}

pub fn setup_wallet(client: Arc<dyn ChainClient>, init_balance: u64) -> Result<Wallet> {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> =
        Arc::new(KeyPair::generate_for_testing(&mut rng0));

    let account = AccountAddress::from_public_key(&account_keypair.public_key);
    let rt = Runtime::new().expect("faucet runtime err.");
    let f = {
        let c = client.clone();
        async move { c.faucet(account, init_balance).await }
    };
    rt.block_on(f)?;

    // enable channel for wallet
    let wallet =
        Wallet::new_with_client(account, account_keypair, client.clone(), TempPath::new())?;
    //    let wallet = Arc::new(wallet);
    let f = {
        let wallet = &wallet;
        async move { wallet.enable_channel().await }
    };
    let gas = rt.block_on(f)?;
    let f = {
        let c = client.clone();
        async move { c.faucet(account, gas).await }
    };
    rt.block_on(f)?;

    let wallet_balance = wallet.balance()?;
    assert_eq!(
        init_balance, wallet_balance,
        "not equal, balance: {:?}",
        wallet_balance
    );
    Ok(wallet)
}

pub fn open_channel(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    sender_fund_amount: u64,
    receiver_fund_amount: u64,
) -> Result<()> {
    let rt = Runtime::new()?;
    let f = async move {
        let sender = sender_wallet.account();
        let receiver = receiver_wallet.account();

        let open_txn = sender_wallet
            .open(receiver, sender_fund_amount, receiver_fund_amount)
            .await?;

        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(sender, &open_txn).await?;
        let receiver_open_txn = match receiver_open_txn {
            Some(t) => t,
            None => {
                receiver_wallet
                    .approve_txn(sender, open_txn.request_id())
                    .await?
            }
        };

        sender_wallet
            .verify_txn_response(receiver, &receiver_open_txn)
            .await?;
        let gas_used = sender_wallet
            .apply_txn(receiver, &receiver_open_txn)
            .await?;
        let _receiver_gas_used = receiver_wallet
            .apply_txn(sender, &receiver_open_txn)
            .await?;

        let (mut events, _) = sender_wallet.client().get_events(
            AccessPath::new_for_channel_global_event(),
            0,
            false,
            1,
        )?;
        let event = events.pop().expect("get channel global event fail.");
        let channel_event = ChannelEvent::make_from(event.event.event_data())?;
        assert_eq!(
            channel_event.channel_address(),
            open_txn.channel_address(),
            "event's channel address {} should equals txn channel address: {}",
            channel_event.channel_address(),
            open_txn.channel_address()
        );

        Ok::<u64, Error>(gas_used)
    };
    rt.block_on(f)?;
    Ok(())
}

pub fn execute_script(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    package_name: &'static str,
    script_name: &'static str,
    args: Vec<TransactionArgument>,
) -> Result<()> {
    let rt = Runtime::new()?;
    let f = async {
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
        Ok::<u64, Error>(gas_used)
    };
    rt.block_on(f)?;
    Ok(())
}

pub fn test_wallet(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    //::libra_logger::try_init_for_testing();
    let sender_amount: u64 = 10_000_000;
    let receiver_amount: u64 = 10_000_000;
    let sender_fund_amount: u64 = 0;
    let receiver_fund_amount: u64 = 0;

    let sender_deposit_amount: u64 = 5_000_000;
    //    let receiver_deposit_amount: u64 = 4_000_000;

    let transfer_amount = 1_000_000;

    let sender_withdraw_amount: u64 = 4_000_000;
    //    let _receiver_withdraw_amount: u64 = 5_000_000;

    let rt = Runtime::new()?;

    let mut sender_wallet = setup_wallet(chain_client.clone(), sender_amount)?;
    let mut receiver_wallet = setup_wallet(chain_client.clone(), receiver_amount)?;
    sender_wallet.start(rt.executor().clone())?;
    receiver_wallet.start(rt.executor().clone())?;

    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    debug!("sender_address: {}", sender);
    debug!("receiver_address: {}", receiver);

    let mut sender_gas_used = 0;

    let f = async move {
        let open_txn = sender_wallet
            .open(receiver, sender_fund_amount, receiver_fund_amount)
            .await?;

        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(sender, &open_txn).await?;
        let receiver_open_txn = match receiver_open_txn {
            Some(t) => t,
            None => {
                receiver_wallet
                    .approve_txn(sender, open_txn.request_id())
                    .await?
            }
        };
        sender_wallet
            .verify_txn_response(receiver, &receiver_open_txn)
            .await?;
        let sender_gas = sender_wallet
            .apply_txn(receiver, &receiver_open_txn)
            .await?;

        let _receiver_gas = receiver_wallet
            .apply_txn(sender, &receiver_open_txn)
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
        sender_gas_used += sender_wallet
            .apply_txn(receiver, &receiver_deposit_txn)
            .await?;
        receiver_wallet
            .apply_txn(sender, &receiver_deposit_txn)
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
        sender_gas_used += sender_wallet
            .apply_txn(receiver, &receiver_transfer_txn)
            .await?;
        let _ = receiver_wallet
            .apply_txn(sender, &receiver_transfer_txn)
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
        sender_gas_used += sender_wallet
            .apply_txn(receiver, &receiver_withdraw_txn)
            .await?;
        receiver_wallet
            .apply_txn(sender, &receiver_withdraw_txn)
            .await?;

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
        Ok::<_, Error>(())
    };

    rt.block_on(f)?;
    Ok(())
}

fn get_test_case_path(case_name: &str) -> PathBuf {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root.join(format!("test_case/{}", case_name))
}

pub(crate) fn deploy_custom_module_and_script(
    wallet1: Arc<Wallet>,
    wallet2: Arc<Wallet>,
    test_case: &str,
) -> Result<()> {
    compile_and_deploy_module(wallet1.clone(), test_case)?;
    sleep(Duration::from_millis(1000));
    let package = compile_package(wallet1.clone(), test_case)?;
    let rt = Runtime::new()?;
    rt.block_on(async {
        wallet1.install_package(package.clone()).await?;
        wallet2.install_package(package).await
    })?;
    Ok(())
}

pub fn compile_and_deploy_module(wallet: Arc<Wallet>, test_case: &str) -> Result<()> {
    let path = get_test_case_path(test_case);
    let module_source = std::fs::read_to_string(path.join("module.mvir"))?;

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    let module_byte_code = compiler.compile_module(module_source.as_str())?;

    let rt = Runtime::new()?;
    let f = async { wallet.deploy_module(module_byte_code).await };
    rt.block_on(f)?;
    Ok(())
}

pub fn compile_package(wallet: Arc<Wallet>, test_case: &str) -> Result<ChannelScriptPackage> {
    let path = get_test_case_path(test_case);

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    compiler.compile_package(path.join("scripts"))
}

pub fn test_deploy_custom_module(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    let rt = Runtime::new()?;
    //::libra_logger::try_init_for_testing();
    let init_balance = 1000000;

    let mut alice = setup_wallet(chain_client.clone(), init_balance)?;
    let mut bob = setup_wallet(chain_client.clone(), init_balance)?;
    alice.start(rt.executor().clone())?;
    bob.start(rt.executor().clone())?;
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_custom_module")?;

    open_channel(alice.clone(), bob.clone(), 100000, 100000)?;

    execute_script(alice.clone(), bob.clone(), "scripts", "do_nothing", vec![])?;

    Ok(())
}

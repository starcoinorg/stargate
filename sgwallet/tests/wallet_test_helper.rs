// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use failure::prelude::*;
use libra_types::{account_address::AccountAddress, transaction::TransactionArgument};
use logger::prelude::*;
use rand::prelude::*;
use sgchain::{
    client_state_view::ClientStateView,
    star_chain_client::{faucet_sync, ChainClient},
};
use sgcompiler::{Compiler, StateViewModuleLoader};
use sgconfig::config::WalletConfig;
use sgtypes::script_package::ChannelScriptPackage;
use sgwallet::wallet::Wallet;
use std::time::Duration;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::sleep,
};
use tokio::runtime::Runtime;

pub fn setup_wallet<C>(client: Arc<C>, init_balance: u64) -> Result<Wallet<C>>
where
    C: ChainClient + Clone + Send + Sync + 'static,
{
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);

    let account = AccountAddress::from_public_key(&account_keypair.public_key);
    faucet_sync(client.as_ref().clone(), account, init_balance)?;
    let wallet = Wallet::new_with_client(
        account,
        account_keypair,
        client,
        WalletConfig::default().store_dir,
    )?;
    assert_eq!(init_balance, wallet.balance()?);
    Ok(wallet)
}

pub fn open_channel<C>(
    sender_wallet: Arc<Wallet<C>>,
    receiver_wallet: Arc<Wallet<C>>,
    sender_fund_amount: u64,
    receiver_fund_amount: u64,
) -> Result<()>
where
    C: ChainClient + Send + Sync + 'static,
{
    let rt = Runtime::new()?;
    let f = async move {
        let sender = sender_wallet.account();
        let receiver = receiver_wallet.account();

        let open_txn = sender_wallet
            .open(receiver, sender_fund_amount, receiver_fund_amount)
            .unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(&open_txn).unwrap();

        let sender_future = sender_wallet.sender_apply_txn(receiver, &receiver_open_txn);
        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &receiver_open_txn);

        let gas_used = sender_future.await.unwrap();
        receiver_future.await.unwrap();
        gas_used
    };
    rt.block_on(f);
    Ok(())
}

pub fn execute_script<C>(
    sender_wallet: Arc<Wallet<C>>,
    receiver_wallet: Arc<Wallet<C>>,
    package_name: &'static str,
    script_name: &'static str,
    args: Vec<TransactionArgument>,
) -> Result<()>
where
    C: ChainClient + Send + Sync + 'static,
{
    let rt = Runtime::new()?;
    let f = async move {
        let sender = sender_wallet.account();
        let receiver = receiver_wallet.account();

        let txn_request = sender_wallet
            .execute_script(receiver, package_name, script_name, args)
            .unwrap();
        let txn_response = receiver_wallet.verify_txn(&txn_request).unwrap();

        let sender_future = sender_wallet.sender_apply_txn(receiver, &txn_response);
        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &txn_response);

        let gas_used = sender_future.await.unwrap();
        receiver_future.await.unwrap();
        gas_used
    };
    rt.block_on(f);
    Ok(())
}

pub fn test_wallet<C>(chain_client: Arc<C>) -> Result<()>
where
    C: ChainClient + Clone + Send + Sync + 'static,
{
    //::logger::try_init_for_testing();
    let sender_amount: u64 = 10_000_000;
    let receiver_amount: u64 = 10_000_000;
    let sender_fund_amount: u64 = 0;
    let receiver_fund_amount: u64 = 0;

    let sender_deposit_amount: u64 = 5_000_000;
    let receiver_deposit_amount: u64 = 4_000_000;

    let transfer_amount = 1_000_000;

    let sender_withdraw_amount: u64 = 4_000_000;
    let receiver_withdraw_amount: u64 = 5_000_000;

    let rt = Runtime::new()?;

    let sender_wallet = Arc::new(setup_wallet(chain_client.clone(), sender_amount).unwrap());
    let receiver_wallet = Arc::new(setup_wallet(chain_client.clone(), receiver_amount).unwrap());

    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    debug!("sender_address: {}", sender);
    debug!("receiver_address: {}", receiver);

    let mut sender_gas_used = 0;

    let f = async move {
        let open_txn = sender_wallet
            .open(receiver, sender_fund_amount, receiver_fund_amount)
            .unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(&open_txn).unwrap();

        let sender_future = sender_wallet.sender_apply_txn(receiver, &receiver_open_txn);
        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &receiver_open_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();

        assert_eq!(sender_channel_balance, sender_fund_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount);
        debug!(
            "after open: sender_channel_balance:{}, receiver_channel_balance:{}",
            sender_channel_balance, receiver_channel_balance
        );

        let deposit_txn = sender_wallet
            .deposit(receiver, sender_deposit_amount, receiver_deposit_amount)
            .unwrap();
        debug_assert!(deposit_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_deposit_txn = receiver_wallet.verify_txn(&deposit_txn).unwrap();

        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &receiver_deposit_txn);
        let sender_future = sender_wallet.sender_apply_txn(receiver, &receiver_deposit_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(
            sender_channel_balance,
            sender_fund_amount + sender_deposit_amount
        );

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(
            receiver_channel_balance,
            receiver_fund_amount + receiver_deposit_amount
        );

        debug!(
            "after deposit: sender_channel_balance:{}, receiver_channel_balance:{}",
            sender_channel_balance, receiver_channel_balance
        );
        let transfer_txn = sender_wallet.transfer(receiver, transfer_amount).unwrap();
        debug_assert!(
            !transfer_txn.is_travel_txn(),
            "transfer_txn must not travel txn"
        );
        //debug!("txn:{:#?}", transfer_txn);

        let receiver_transfer_txn = receiver_wallet.verify_txn(&transfer_txn).unwrap();

        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &receiver_transfer_txn);
        let sender_future = sender_wallet.sender_apply_txn(receiver, &receiver_transfer_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(
            sender_channel_balance,
            sender_fund_amount + sender_deposit_amount - transfer_amount
        );

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(
            receiver_channel_balance,
            receiver_fund_amount + receiver_deposit_amount + transfer_amount
        );

        debug!(
            "after transfer: sender_channel_balance:{}, receiver_channel_balance:{}",
            sender_channel_balance, receiver_channel_balance
        );
        let withdraw_txn = sender_wallet
            .withdraw(receiver, sender_withdraw_amount, receiver_withdraw_amount)
            .unwrap();
        debug_assert!(withdraw_txn.is_travel_txn(), "withdraw_txn must travel txn");
        //debug!("txn:{:#?}", withdraw_txn);

        let receiver_withdraw_txn = receiver_wallet.verify_txn(&withdraw_txn).unwrap();

        let receiver_future = receiver_wallet.receiver_apply_txn(sender, &receiver_withdraw_txn);
        let sender_future = sender_wallet.sender_apply_txn(receiver, &receiver_withdraw_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(
            sender_channel_balance,
            sender_fund_amount + sender_deposit_amount - transfer_amount - sender_withdraw_amount
        );

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(
            receiver_channel_balance,
            receiver_fund_amount + receiver_deposit_amount + transfer_amount
                - receiver_withdraw_amount
        );

        debug!(
            "after withdraw: sender_channel_balance:{}, receiver_channel_balance:{}",
            sender_channel_balance, receiver_channel_balance
        );

        let sender_balance = sender_wallet.balance().unwrap();
        let receiver_balance = receiver_wallet.balance().unwrap();

        assert_eq!(
            sender_balance,
            sender_amount - sender_gas_used - sender_fund_amount - sender_deposit_amount
                + sender_withdraw_amount
        );
        assert_eq!(
            receiver_balance,
            receiver_amount - receiver_fund_amount - receiver_deposit_amount
                + receiver_withdraw_amount
        );

        drop(sender_wallet);
        drop(receiver_wallet);
        debug!("finish");
    };

    rt.block_on(f);
    Ok(())
}

fn get_test_case_path(case_name: &str) -> PathBuf {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root.join(format!("test_case/{}", case_name))
}

pub(crate) fn deploy_custom_module_and_script<C>(
    wallet1: Arc<Wallet<C>>,
    wallet2: Arc<Wallet<C>>,
    test_case: &str,
) -> Result<()>
where
    C: ChainClient + Send + Sync + 'static,
{
    compile_and_deploy_module(wallet1.clone(), test_case)?;
    sleep(Duration::from_millis(1000));
    let package = compile_package(wallet1.clone(), test_case)?;
    wallet1.install_package(package.clone())?;
    sleep(Duration::from_millis(1000));
    wallet2.install_package(package)?;
    Ok(())
}

pub fn compile_and_deploy_module<C>(wallet: Arc<Wallet<C>>, test_case: &str) -> Result<()>
where
    C: ChainClient + Send + Sync + 'static,
{
    let path = get_test_case_path(test_case);
    let module_source = std::fs::read_to_string(path.join("module.mvir")).unwrap();

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    let module_byte_code = compiler.compile_module(module_source.as_str())?;

    let rt = Runtime::new()?;
    let f = async move {
        wallet.deploy_module(module_byte_code).await.unwrap();
    };
    rt.block_on(f);
    Ok(())
}

pub fn compile_package<C>(wallet: Arc<Wallet<C>>, test_case: &str) -> Result<ChannelScriptPackage>
where
    C: ChainClient + Send + Sync + 'static,
{
    let path = get_test_case_path(test_case);

    let client_state_view = ClientStateView::new(None, wallet.client());
    let module_loader = StateViewModuleLoader::new(&client_state_view);
    let compiler = Compiler::new_with_module_loader(wallet.account(), &module_loader);
    compiler.compile_package(path.join("scripts"))
}

pub fn test_deploy_custom_module<C>(chain_client: Arc<C>) -> Result<()>
where
    C: ChainClient + Clone + Send + Sync + 'static,
{
    //::logger::try_init_for_testing();
    let init_balance = 1000000;

    let alice = Arc::new(setup_wallet(chain_client.clone(), init_balance)?);
    let bob = Arc::new(setup_wallet(chain_client.clone(), init_balance)?);
    deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_custom_module")?;

    open_channel(alice.clone(), bob.clone(), 100000, 100000)?;

    execute_script(alice.clone(), bob.clone(), "scripts", "do_nothing", vec![])?;

    Ok(())
}

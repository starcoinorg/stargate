use std::sync::Arc;
use std::thread::sleep;

use futures::future::Future;
use rand::prelude::*;
use tokio::runtime::{Runtime, TaskExecutor};

use {
    futures_03::{
        future::{FutureExt, TryFutureExt},
    },
};
use chain_client::{ChainClient, RpcChainClient};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::test_utils::KeyPair;
use crypto::Uniform;
use failure::_core::time::Duration;
use failure::prelude::*;
use logger::prelude::*;
use mock_chain_client::{MockChainClient, mock_star_client::MockStarClient};
use types::account_address::AccountAddress;

use super::wallet::*;
use tokio::runtime::current_thread::block_on_all;
use star_types::script_package::ChannelScriptPackage;
use types::transaction::TransactionArgument;


pub fn setup_wallet<C>(client: Arc<C>, executor: TaskExecutor, init_balance: u64)  -> Result<Wallet<C>> where
    C: ChainClient + Send + Sync + 'static{
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng0);

    let account = AccountAddress::from_public_key(&account_keypair.public_key);
    client.faucet(account, init_balance)?;
    let wallet = Wallet::new_with_client(executor, account, account_keypair, client)?;
    assert_eq!(init_balance, wallet.balance()?);
    Ok(wallet)
}

pub fn open_channel<C>(sender_wallet: Arc<Wallet<C>>, receiver_wallet: Arc<Wallet<C>>, sender_fund_amount: u64, receiver_fund_amount: u64) -> Result<()> where
    C: ChainClient + Send + Sync + 'static{
    let mut rt = Runtime::new()?;
    let f = async move {
        let sender = sender_wallet.account();
        let receiver = receiver_wallet.account();

        let open_txn = sender_wallet.open(receiver, sender_fund_amount, receiver_fund_amount).unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(&open_txn).unwrap();

        let sender_future = sender_wallet.apply_txn(receiver, &receiver_open_txn);
        let receiver_future = receiver_wallet.apply_txn(sender, &receiver_open_txn);

        let gas_used = sender_future.await.unwrap();
        receiver_future.await.unwrap();
        gas_used
    };
    rt.block_on(f.boxed().unit_error().compat()).unwrap();
    Ok(())
}

pub fn execute_script<C>(sender_wallet: Arc<Wallet<C>>, receiver_wallet: Arc<Wallet<C>>, package_name: &'static str, script_name: &'static str, args: Vec<TransactionArgument>) -> Result<()> where
    C: ChainClient + Send + Sync + 'static{
    let mut rt = Runtime::new()?;
    let f = async move {
        let sender = sender_wallet.account();
        let receiver = receiver_wallet.account();

        let txn_request = sender_wallet.execute_script(receiver, package_name, script_name, args).unwrap();
        let txn_response = receiver_wallet.verify_txn(&txn_request).unwrap();

        let sender_future = sender_wallet.apply_txn(receiver, &txn_response);
        let receiver_future = receiver_wallet.apply_txn(sender, &txn_response);

        let gas_used = sender_future.await.unwrap();
        receiver_future.await.unwrap();
        gas_used
    };
    rt.block_on(f.boxed().unit_error().compat()).unwrap();
    Ok(())
}


#[test]
fn test_wallet() -> Result<()> {
    ::logger::init_for_e2e_testing();
    let sender_amount: u64 = 10_000_000;
    let receiver_amount: u64 = 10_000_000;
    let sender_fund_amount: u64 = 0;
    let receiver_fund_amount: u64 = 0;

    let sender_deposit_amount: u64 = 5_000_000;
    let receiver_deposit_amount: u64 = 4_000_000;

    let transfer_amount = 1_000_000;

    let sender_withdraw_amount: u64 = 4_000_000;
    let receiver_withdraw_amount: u64 = 5_000_000;

    let mut rt = Runtime::new()?;
    let executor = rt.executor();

    let (mock_chain_service, handle) = MockStarClient::new();
    let client = Arc::new(mock_chain_service);

    let sender_wallet = Arc::new(setup_wallet(client.clone(), executor.clone(),sender_amount).unwrap());
    sleep(Duration::from_secs(5));
    let receiver_wallet = Arc::new(setup_wallet(client.clone(),executor.clone(), receiver_amount).unwrap());

    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    debug!("sender_address: {}", sender);
    debug!("receiver_address: {}", receiver);

    let mut sender_gas_used = 0;

    let f = async move {

        let open_txn = sender_wallet.open(receiver, sender_fund_amount, receiver_fund_amount).unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(&open_txn).unwrap();

        let sender_future = sender_wallet.apply_txn(receiver, &receiver_open_txn);
        let receiver_future = receiver_wallet.apply_txn(sender, &receiver_open_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();

        assert_eq!(sender_channel_balance, sender_fund_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount);
        debug!("after open: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);

        let deposit_txn = sender_wallet.deposit(receiver, sender_deposit_amount, receiver_deposit_amount).unwrap();
        debug_assert!(deposit_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_deposit_txn = receiver_wallet.verify_txn(&deposit_txn).unwrap();

        let receiver_future = receiver_wallet.apply_txn(sender,&receiver_deposit_txn);
        let sender_future = sender_wallet.apply_txn(receiver,&receiver_deposit_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount + receiver_deposit_amount);

        debug!("after deposit: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);
        let transfer_txn = sender_wallet.transfer(receiver, transfer_amount).unwrap();
        debug_assert!(!transfer_txn.is_travel_txn(), "transfer_txn must not travel txn");
        //debug!("txn:{:#?}", transfer_txn);

        let receiver_transfer_txn = receiver_wallet.verify_txn(&transfer_txn).unwrap();

        let receiver_future = receiver_wallet.apply_txn(sender,&receiver_transfer_txn);
        let sender_future = sender_wallet.apply_txn(receiver, &receiver_transfer_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount - transfer_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount + receiver_deposit_amount + transfer_amount);

        debug!("after transfer: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);
        let withdraw_txn = sender_wallet.withdraw(receiver, sender_withdraw_amount, receiver_withdraw_amount).unwrap();
        debug_assert!(withdraw_txn.is_travel_txn(), "withdraw_txn must travel txn");
        //debug!("txn:{:#?}", withdraw_txn);

        let receiver_withdraw_txn = receiver_wallet.verify_txn(&withdraw_txn).unwrap();

        let receiver_future = receiver_wallet.apply_txn(sender,&receiver_withdraw_txn);
        let sender_future = sender_wallet.apply_txn(receiver,&receiver_withdraw_txn);

        sender_gas_used += sender_future.await.unwrap();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount - transfer_amount - sender_withdraw_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount + receiver_deposit_amount + transfer_amount - receiver_withdraw_amount);

        debug!("after withdraw: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);

        let sender_balance = sender_wallet.balance().unwrap();
        let receiver_balance = receiver_wallet.balance().unwrap();

        assert_eq!(sender_balance, sender_amount - sender_gas_used - sender_fund_amount - sender_deposit_amount + sender_withdraw_amount);
        assert_eq!(receiver_balance, receiver_amount - receiver_fund_amount - receiver_deposit_amount + receiver_withdraw_amount);

        drop(sender_wallet);
        drop(receiver_wallet);
        debug!("finish");
    };

    rt.block_on(f.boxed().unit_error().compat()).unwrap();
    Ok(())
}

#[test]
fn test_wallet_install_package() -> Result<()>{
    let init_balance = 1000000;
    let mut rt = Runtime::new()?;
    let executor = rt.executor();

    let (mock_chain_service, handle) = MockChainClient::new(executor.clone());
    let client = Arc::new(mock_chain_service);

    let alice = Arc::new(setup_wallet(client.clone(), executor.clone(),init_balance)?);
    let bob = Arc::new(setup_wallet(client.clone(), executor.clone(),init_balance)?);

    let transfer_code = alice.get_script("libra", "transfer").unwrap();
    let package = ChannelScriptPackage::new("test".to_string(), vec![transfer_code]);
    alice.install_package(package.clone())?;
    bob.install_package(package.clone())?;

    open_channel(alice.clone(), bob.clone(), 100000, 100000)?;

    execute_script(alice.clone(), bob.clone(), "test", "transfer", vec![TransactionArgument::U64(10000)])?;
    Ok(())
}
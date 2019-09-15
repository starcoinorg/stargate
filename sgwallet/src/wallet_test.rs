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
use mock_chain_client::MockChainClient;
use types::account_address::AccountAddress;

use super::wallet::*;
use tokio::runtime::current_thread::block_on_all;

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

    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let mut rng1: StdRng = SeedableRng::from_seed([1; 32]);

    let sender_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng0);
    let receiver_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng1);

    let mut rt = Runtime::new()?;
    let executor = rt.executor();

    let (mock_chain_service, db_shutdown_receiver) = MockChainClient::new(executor.clone());
    let client = Arc::new(mock_chain_service);
    let sender = AccountAddress::from_public_key(&sender_keypair.public_key);
    let receiver = AccountAddress::from_public_key(&receiver_keypair.public_key);

    debug!("sender_address: {}", sender);
    debug!("receiver_address: {}", receiver);

    client.faucet(sender, sender_amount)?;
    client.faucet(receiver, receiver_amount)?;

    let sender_wallet = Arc::new(Wallet::new_with_client(executor.clone(), sender, sender_keypair, client.clone()).unwrap());
    let receiver_wallet = Arc::new(Wallet::new_with_client(executor.clone(), receiver, receiver_keypair, client).unwrap());

    assert_eq!(sender_amount, sender_wallet.balance());
    assert_eq!(receiver_amount, receiver_wallet.balance());

    let mut sender_gas_used = 0;

    let f = async move {

        let open_txn = sender_wallet.open(receiver, sender_fund_amount, receiver_fund_amount).unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_open_txn = receiver_wallet.verify_txn(&open_txn).unwrap();

        let sender_future = sender_wallet.apply_txn(&receiver_open_txn);
        let receiver_future = receiver_wallet.apply_txn(&open_txn);

        sender_gas_used += sender_future.await.unwrap().gas_used();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();

        assert_eq!(sender_channel_balance, sender_fund_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount);
        debug!("after open: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);

        let deposit_txn = sender_wallet.deposit(receiver, sender_deposit_amount, receiver_deposit_amount).unwrap();
        debug_assert!(deposit_txn.is_travel_txn(), "open_txn must travel txn");

        let receiver_deposit_txn = receiver_wallet.verify_txn(&deposit_txn).unwrap();

        let receiver_future = receiver_wallet.apply_txn(&deposit_txn);
        let sender_future = sender_wallet.apply_txn(&receiver_deposit_txn);

        sender_gas_used += sender_future.await.unwrap().gas_used();
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

        let receiver_future = receiver_wallet.apply_txn(&transfer_txn);
        let sender_future = sender_wallet.apply_txn(&receiver_transfer_txn);

        sender_gas_used += sender_future.await.unwrap().gas_used();
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

        let receiver_future = receiver_wallet.apply_txn(&withdraw_txn);
        let sender_future = sender_wallet.apply_txn(&receiver_withdraw_txn);

        sender_gas_used += sender_future.await.unwrap().gas_used();
        receiver_future.await.unwrap();

        let sender_channel_balance = sender_wallet.channel_balance(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount - transfer_amount - sender_withdraw_amount);

        let receiver_channel_balance = receiver_wallet.channel_balance(sender).unwrap();
        assert_eq!(receiver_channel_balance, receiver_fund_amount + receiver_deposit_amount + transfer_amount - receiver_withdraw_amount);

        debug!("after withdraw: sender_channel_balance:{}, receiver_channel_balance:{}",sender_channel_balance,receiver_channel_balance);

        let sender_balance = sender_wallet.balance();
        let receiver_balance = receiver_wallet.balance();

        assert_eq!(sender_balance, sender_amount - sender_gas_used - sender_fund_amount - sender_deposit_amount + sender_withdraw_amount);
        assert_eq!(receiver_balance, receiver_amount - receiver_fund_amount - receiver_deposit_amount + receiver_withdraw_amount);

        drop(sender_wallet);
        drop(receiver_wallet);
        debug!("finish");
    };

    rt.block_on(f.boxed().unit_error().compat()).unwrap();
    //db_shutdown_receiver.recv().expect("db_shutdown_receiver err.");
    Ok(())
}

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
use types::account_config::coin_struct_tag;

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

    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let mut rng1: StdRng = SeedableRng::from_seed([1; 32]);

    let sender_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng0);
    let receiver_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng1);

    let mut rt = Runtime::new()?;
    let executor = rt.executor();


    let client = Arc::new(MockChainClient::new(executor.clone()));
    let sender = AccountAddress::from_public_key(&sender_keypair.public_key);
    let receiver = AccountAddress::from_public_key(&receiver_keypair.public_key);

    debug!("sender_address: {}", sender);
    debug!("receiver_address: {}", receiver);
    client.faucet(sender, sender_amount)?;
    client.faucet(receiver, receiver_amount)?;

    let wallet = Arc::new(Wallet::new_with_client(executor.clone(), sender, sender_keypair, client).unwrap());

    assert_eq!(sender_amount, wallet.balance());

    let f = async move {

        let open_txn = wallet.open(receiver, sender_fund_amount, receiver_fund_amount).unwrap();
        debug_assert!(open_txn.is_travel_txn(), "open_txn must travel txn");

        wallet.apply_txn(&open_txn).await.unwrap();
        let sender_channel_balance = wallet.channel_balance_default(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount);


        let deposit_txn = wallet.deposit_default(receiver, sender_deposit_amount, receiver_deposit_amount).unwrap();
        debug_assert!(deposit_txn.is_travel_txn(), "open_txn must travel txn");

        wallet.apply_txn(&deposit_txn).await.unwrap();
        let sender_channel_balance = wallet.channel_balance_default(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount);

        let transfer_txn = wallet.transfer_default(receiver, transfer_amount).unwrap();
        debug_assert!(!transfer_txn.is_travel_txn(), "transfer_txn must not travel txn");
        //debug!("txn:{:#?}", transfer_txn);

        wallet.apply_txn(&transfer_txn).await.unwrap();
        let sender_channel_balance = wallet.channel_balance_default(receiver).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount + sender_deposit_amount - transfer_amount);

        let sender_channel_balance = wallet.channel_balance_default(receiver).unwrap();

        let withdraw_txn = wallet.withdraw_default(receiver, sender_channel_balance, 1).unwrap();
        debug_assert!(withdraw_txn.is_travel_txn(), "withdraw_txn must travel txn");
        //debug!("txn:{:#?}", withdraw_txn);

        wallet.apply_txn(&withdraw_txn).await.unwrap();
        let sender_channel_balance = wallet.channel_balance_default(receiver).unwrap();
        assert_eq!(sender_channel_balance, 0);

        debug!("finish");

    };

    rt.block_on(f.boxed().unit_error().compat());
    Ok(())
}

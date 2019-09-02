use std::sync::Arc;

use rand::prelude::*;

use chain_client::{ChainClient, RpcChainClient};
use mock_chain_client::MockChainClient;
use crypto::test_utils::KeyPair;
use crypto::Uniform;
use types::account_address::AccountAddress;

use super::wallet::*;
use types::account_config::coin_struct_tag;
use logger::prelude::*;
use std::thread::sleep;
use failure::_core::time::Duration;
use tokio::runtime::{Runtime,TaskExecutor};
use failure::prelude::*;
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use {
    futures_03::{
        future::{FutureExt,TryFutureExt},
    },
};
use futures::future::Future;

#[test]
fn test_wallet() -> Result<()> {
    ::logger::init_for_e2e_testing();
    let sender_amount: u64 = 10_000_000;
    let receiver_amount: u64 = 10_000_000;
    let sender_fund_amount: u64 = 5_000_000;
    let receiver_fund_amount: u64 = 4_000_000;
    let transfer_amount = 1_000_000;

    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let mut rng1: StdRng = SeedableRng::from_seed([1; 32]);

    let sender_keypair:KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng0);
    let receiver_keypair:KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng1);

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
    let asset_tag = coin_struct_tag();
    let fund_txn = wallet.fund(asset_tag.clone(), receiver,sender_fund_amount, receiver_fund_amount)?;
    debug_assert!(fund_txn.is_travel_txn(), "fund_txn must travel txn");

    //debug!("txn:{:#?}", fund_txn);
    let wallet_arc = wallet.clone();
    let asset_tag_clone = asset_tag.clone();
    let f = async move{
        wallet_arc.apply_txn(&fund_txn).await;
        let sender_channel_balance = wallet_arc.channel_balance(receiver,asset_tag_clone).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount);
    };
    executor.spawn(f.boxed().unit_error().compat());

    let transfer_txn = wallet.transfer(asset_tag.clone(), receiver, transfer_amount)?;
    debug_assert!(!transfer_txn.is_travel_txn(), "transfer_txn must not travel txn");
    //debug!("txn:{:#?}", transfer_txn);

    let wallet_arc = wallet.clone();
    let asset_tag_clone = asset_tag.clone();
    let transfer_txn_clone = transfer_txn.clone();
    let f = async move{
        wallet_arc.apply_txn(&transfer_txn_clone).await;
        let sender_channel_balance = wallet_arc.channel_balance(receiver,asset_tag_clone).unwrap();
        assert_eq!(sender_channel_balance, sender_fund_amount - transfer_amount);
    };
    executor.spawn(f.boxed().unit_error().compat());

    let sender_channel_balance = wallet.channel_balance(receiver,asset_tag.clone())?;

    let withdraw_txn = wallet.withdraw(asset_tag.clone(), receiver, sender_channel_balance, 1)?;
    debug_assert!(withdraw_txn.is_travel_txn(), "withdraw_txn must travel txn");
    //debug!("txn:{:#?}", withdraw_txn);

    let wallet_arc = wallet.clone();
    let asset_tag_clone = asset_tag.clone();
    let f = async move{
        wallet_arc.apply_txn(&transfer_txn).await;
        let sender_channel_balance = wallet_arc.channel_balance(receiver,asset_tag_clone).unwrap();
        assert_eq!(sender_channel_balance, 0);

    };
    executor.spawn(f.boxed().unit_error().compat());

    rt.shutdown_on_idle().wait().unwrap();

    Ok(())
}

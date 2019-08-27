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

#[test]
fn test_wallet() {
    ::logger::init_for_e2e_testing();
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);

    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let client = Arc::new(MockChainClient::new(executor));
    //TODO faucet by transaction.
    //wait genesis tx finish.
    //sleep(Duration::from_millis(1000));
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    debug!("account_address: {}", account_address);
    client.faucet(account_address, amount).unwrap();
    let wallet = Wallet::new_with_client(account_address, keypair, client).unwrap();
    assert_eq!(amount, wallet.balance());

    let account_address2 = AccountAddress::random();
    let transfer_amount = 1_000_000;
    let offchain_txn = wallet.transfer(coin_struct_tag(), account_address2, transfer_amount).unwrap();
    debug!("txn:{:#?}", offchain_txn);
    wallet.apply_txn(&offchain_txn).unwrap();
    assert_eq!(amount - transfer_amount - offchain_txn.output().gas_used(), wallet.balance());
    let account_state_blob = wallet.get_account_state();
    debug_assert!(account_state_blob.len() > 0);
}

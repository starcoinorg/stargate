use super::wallet::*;
use nextgen_crypto::test_utils::KeyPair;
use nextgen_crypto::Uniform;
use rand::prelude::*;
use std::sync::Arc;
use chain_client::{RpcChainClient, ChainClient};
use mock_chain_client::MockChainClient;
use types::account_address::AccountAddress;

#[test]
fn test_wallet(){
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let client = Arc::new(MockChainClient::new());
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    client.faucet(account_address, 100).unwrap();
    let wallet = Wallet::new_with_client(account_address,keypair, client).unwrap();
}
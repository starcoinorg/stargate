use super::wallet::*;
use nextgen_crypto::test_utils::KeyPair;
use nextgen_crypto::Uniform;
use rand::prelude::*;
use std::sync::Arc;
use chain_client::RpcChainClient;

#[test]
fn test_wallet(){
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let rpc_host = "localhost";
    let rpc_port = 8080;
    let client = Arc::new(RpcChainClient::new(rpc_host, rpc_port));
    let wallet = Wallet::new_with_client(keypair, client).unwrap();
}
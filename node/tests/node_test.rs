#![feature(async_await)]

use futures::{
    io::{AsyncReadExt},
    sink::{SinkExt},
    future::{FutureExt},
    compat::{Sink01CompatExt} ,
    prelude::*,
};
use memsocket::{MemorySocket};
use netcore::transport::{memory::MemoryTransport};
use std::io::Result;
use tokio::runtime::{Runtime};
use node::node::Node;
use switch::{switch::Switch};
use tokio::codec::{Framed,LengthDelimitedCodec};
use bytes::Bytes;

use std::sync::Arc;

use rand::prelude::*;

use chain_client::{ChainClient, RpcChainClient};
use mock_chain_client::MockChainClient;
use nextgen_crypto::test_utils::KeyPair;
use nextgen_crypto::Uniform;
use types::account_address::AccountAddress;

use sgwallet::wallet::*;

#[test]
fn start_server_test() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let switch:Switch<MemorySocket> = Switch::new();

    let amount: u64 = 1_000_000_000;
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let client = Arc::new(MockChainClient::new());
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    client.faucet(account_address, amount).unwrap();
    let mut wallet = Wallet::new_with_client(account_address, keypair.clone(), client).unwrap();

    let node = Node::new(switch,wallet,keypair.clone());

    node.start_server(&executor,MemoryTransport::default(),"/memory/10".parse().unwrap());
        
    let mut dialer=MemorySocket::connect(10).unwrap();
    let mut stream = Framed::new(dialer.compat(), LengthDelimitedCodec::new()).sink_compat();

    let f=async move{
        stream.send(Bytes::from("hello")).await.unwrap();
        let result = stream.next().await;   
        match result {
            Some(Ok(data)) => {assert_eq!(&data[..],b"hello");  },
            Some(Err(_)) => println!("error"),
            None    => println!("Cannot divide by 0"),
        }              
                      
    };
    executor.spawn(f.boxed()
            .unit_error()
            .compat(),);
    //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}
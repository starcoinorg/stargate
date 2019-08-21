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
use tokio::runtime::{Runtime,TaskExecutor};
use node::node::Node;
use switch::{switch::Switch};
use tokio::codec::{Framed,LengthDelimitedCodec};
use bytes::Bytes;

use rand::prelude::*;

use chain_client::{ChainClient, RpcChainClient};
use mock_chain_client::MockChainClient;
use crypto::test_utils::KeyPair;
use crypto::Uniform;
use types::account_address::AccountAddress;
use star_types::message::{*};
use sgwallet::wallet::*;
use crypto::hash::{CryptoHasher, TestOnlyHasher};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::traits::SigningKey;
use std::sync::{Arc,Mutex};
use futures_01::future::Future as Future01;
use std::time::{SystemTime,UNIX_EPOCH};
use types::account_config::coin_struct_tag;
use logger::prelude::*;


#[test]
fn start_server_test() -> Result<()> {
    ::logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mut node1,addr1,keypair1) = gen_node(executor.clone());
    node1.start_server("/memory/10".parse().unwrap());
        
    let (mut node2,addr2,keypair2) = gen_node(executor.clone());
    node2.start_server("/memory/20".parse().unwrap());

    node2.connect("/memory/10".parse().unwrap(),addr1);
    
    let neg_msg = create_negotiate_message(addr2,addr1 ,keypair2.private_key);
    node2.open_channel_negotiate(neg_msg);

    let transfer_amount = 1_000_000;
    let offchain_txn = node1.off_chain_pay(coin_struct_tag(), addr2, transfer_amount).unwrap();
    debug!("txn:{:#?}", offchain_txn);

    //wallet.apply_txn(&offchain_txn);
    //assert_eq!(amount - transfer_amount - offchain_txn.output().gas_used(), wallet.balance());


/*     
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
 */ //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}

fn gen_node(executor:TaskExecutor)->(Node<MockChainClient,MemoryTransport>,AccountAddress,KeyPair<Ed25519PrivateKey,Ed25519PublicKey>){
    let switch:Switch<MemorySocket> = Switch::new();

    let amount: u64 = 1_000_000_000;    
    let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts());//SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let client = Arc::new(MockChainClient::new());
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    client.faucet(account_address, amount).unwrap();
    let mut wallet = Wallet::new_with_client(account_address, keypair.clone(), client).unwrap();

    (Node::new(executor.clone(),wallet,keypair.clone(),MemoryTransport::default()),account_address,keypair)
}

fn create_negotiate_message(sender_addr:AccountAddress,receiver_addr:AccountAddress,private_key:Ed25519PrivateKey)->OpenChannelNodeNegotiateMessage{
    let resource_type = StructTag::new(sender_addr,"test".to_string(),"test".to_string(),vec![]);
    let rtx = RawNegotiateMessage::new(sender_addr,resource_type,10,receiver_addr,20);
    let mut hasher = TestOnlyHasher::default();
    hasher.write(&rtx.clone().into_proto_bytes().unwrap());
    let hash_value = hasher.finish();
    let sender_sign=private_key.sign_message(&hash_value);
    OpenChannelNodeNegotiateMessage::new(rtx,sender_sign,None)
}

fn get_unix_ts()->u64{
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");;   
    since_the_epoch.as_millis() as u64
}
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

use std::sync::Arc;

use rand::prelude::*;

use chain_client::{ChainClient, RpcChainClient};
use mock_chain_client::MockChainClient;
use nextgen_crypto::test_utils::KeyPair;
use nextgen_crypto::Uniform;
use types::account_address::AccountAddress;
use star_types::message::{*};
use sgwallet::wallet::*;
use crypto::hash::{CryptoHasher, TestOnlyHasher};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::traits::SigningKey;


#[test]
fn start_server_test() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (node1,addr1,keypair1) = gen_node(executor.clone());
    node1.start_server(MemoryTransport::default(),"/memory/10".parse().unwrap());
        
    let (node2,addr2,keypair2) = gen_node(executor.clone());
    node2.start_server(MemoryTransport::default(),"/memory/20".parse().unwrap());

    let transport = MemoryTransport::default();
    node2.connect(transport,"/memory/10".parse().unwrap());

    let neg_msg = create_negotiate_message(addr2,addr1 ,keypair2.private_key);
    node2.open_channel_negotiate(neg_msg);
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
 */    //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}

fn gen_node(executor:TaskExecutor)->(Node<MemorySocket,MockChainClient>,AccountAddress,KeyPair<Ed25519PrivateKey,Ed25519PublicKey>){
    let switch:Switch<MemorySocket> = Switch::new();

    let amount: u64 = 1_000_000_000;
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let client = Arc::new(MockChainClient::new());
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    println!("account_address: {}", account_address);
    client.faucet(account_address, amount).unwrap();
    let mut wallet = Wallet::new_with_client(account_address, keypair.clone(), client).unwrap();

    (Node::new(executor.clone(),switch,wallet,keypair.clone()),account_address,keypair)
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
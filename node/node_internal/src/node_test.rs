#![feature(async_await)]

use futures::{
    io::{AsyncReadExt},
    sink::{SinkExt},
    future::{FutureExt},
    compat::{Sink01CompatExt} ,
    prelude::*,
};
use network::{build_network_service,NetworkService};
//use std::io::Result;
use failure::prelude::*;

use tokio::runtime::{Runtime,TaskExecutor};

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
use logger::prelude::*;
use sg_config::config::NetworkConfig;
use crate::test_helper::{*};
use crate::node::Node;
use futures::compat::Future01CompatExt;
use std::time::{Duration, Instant};
use tokio::timer::Delay;

#[test]
fn node_test() -> Result<()> {
    ::logger::init_for_e2e_testing();
    env_logger::init();
    let mut rt1 = Runtime::new().unwrap();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service, db_shutdown_receiver) = MockChainClient::new(executor.clone());
    let client= Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config("/ip4/127.0.0.1/tcp/5000".to_string(),vec![]);
    let (mut node1,addr1,keypair1) = gen_node(executor.clone(),&network_config1,client.clone());
    node1.start_server();

    let addr1_hex=hex::encode(addr1);

    let seed = format!("{}/p2p/{}","/ip4/127.0.0.1/tcp/5000".to_string(),addr1_hex);
    let network_config2 = create_node_network_config("/ip4/127.0.0.1/tcp/5001".to_string(),vec![seed]);
    let (mut node2,addr2,keypair2) = gen_node(executor.clone(),&network_config2,client.clone());
    node2.start_server();

    let f = async move {
        let neg_msg = create_negotiate_message(addr2, addr1, keypair2.private_key);
        node2.open_channel_negotiate(neg_msg);

        let fund_amount = 1000000;
        node2.open_channel_async(addr1, fund_amount, fund_amount).unwrap().compat().await.unwrap();

        assert_eq!(node2.channel_balance(addr1).unwrap(), fund_amount);
        assert_eq!(node1.channel_balance(addr2).unwrap(), fund_amount);

        let deposit_amount = 10000;
        node2.deposit_async( addr1, deposit_amount, deposit_amount).unwrap().compat().await.unwrap();

        delay(Duration::from_millis(100)).await;
        assert_eq!(node2.channel_balance(addr1).unwrap(), fund_amount + deposit_amount);
        assert_eq!(node1.channel_balance(addr2).unwrap(), fund_amount + deposit_amount);

        let transfer_amount = 1_000;
        let offchain_txn = node2.off_chain_pay_async( addr1, transfer_amount).unwrap().compat().await.unwrap();
        debug!("txn:{:#?}", offchain_txn);

        assert_eq!(node2.channel_balance(addr1).unwrap(), fund_amount - transfer_amount + deposit_amount);
        assert_eq!(node1.channel_balance(addr2).unwrap(), fund_amount + transfer_amount + deposit_amount);

        let wd_amount = 10000;
        node2.withdraw_async( addr1, wd_amount, wd_amount).unwrap().compat().await.unwrap();

        delay(Duration::from_millis(100)).await;
        assert_eq!(node2.channel_balance(addr1).unwrap(), fund_amount - transfer_amount - wd_amount + deposit_amount);
        assert_eq!(node1.channel_balance(addr2).unwrap(), fund_amount + transfer_amount - wd_amount + deposit_amount);

        node1.shutdown();
        node2.shutdown();

    };
    rt.block_on(f.boxed().unit_error().compat()).unwrap();

    drop(client);
    //db_shutdown_receiver.recv().expect("db shutdown msg err.");

    debug!("here");
    //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}

async fn delay(duration:Duration){
    let timeout_time = Instant::now() + duration;
    Delay::new(timeout_time).compat().await.unwrap();
}

#[test]
fn error_test()->Result<()>{
    ::logger::init_for_e2e_testing();
    env_logger::init();

    match new_error() {
        Err(e) => {
            if let Some(err) = e.downcast_ref::<SgError>() {
                info!("this is a sg error");
                assert_eq!(1,1)
            } else {
                // fallback case
                info!("this is a common error");
                assert_eq!(1,2)
            }
        }
        Ok(_) => {info!("ok")}
    };
    Ok(())
}

fn new_error()->Result<()>{
    Err(SgError::new(star_types::sg_error::SgErrorCode::UNKNOWN,"111".to_string()).into())
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

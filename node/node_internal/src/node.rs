use switch::{switch::Switch};
use netcore::transport::{Transport};
use parity_multiaddr::Multiaddr;
use tokio::{codec::{Framed,LengthDelimitedCodec}, runtime::TaskExecutor};
use futures::{
    compat::{Sink01CompatExt,Stream01CompatExt,Compat01As03Sink,Compat01As03},
    future::{FutureExt,Future},
    stream::{Stream,Fuse,StreamExt,FuturesUnordered},
    io::{AsyncRead, AsyncWrite},
    prelude::*,
    sink::{SinkExt},
};
use std::sync::{Arc,Mutex};
use sgwallet::wallet::Wallet;
use chain_client::{ChainClient};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::SigningKey;
use crypto::test_utils::KeyPair;
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use std::collections::HashMap;
use types::account_address::AccountAddress;
use failure::prelude::*;
use std::{thread, time};
use logger::prelude::*;
use network::{
    {NetworkService,Message}
};
use futures_01::sync::mpsc::{UnboundedSender,UnboundedReceiver};
use state_storage::AccountState;
use std::borrow::Borrow;
use types::account_config::AccountResource;


pub struct Node <C: ChainClient+Send+Sync+'static>{
    executor: TaskExecutor,
    node_inner:Arc<Mutex<NodeInner<C>>>,
}

struct NodeInner<C: ChainClient+Send+Sync+'static> {
    wallet:Wallet<C>,
    executor:TaskExecutor,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    network_service:NetworkService,
    sender:UnboundedSender<Message>,
    receiver:Option<UnboundedReceiver<Message>>,
}

impl<C:ChainClient+Send+Sync+'static> Node<C>{

    pub fn new(executor: TaskExecutor,wallet:Wallet<C>,keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
               network_service:NetworkService,sender:UnboundedSender<Message>,receiver:UnboundedReceiver<Message>)->Self{
        let executor_clone = executor.clone();

        let node_inner=NodeInner{
            executor:executor_clone,
            keypair,
            wallet,
            network_service,
            sender,
            receiver:Some(receiver)
        };
        Self{
            executor,
            node_inner:Arc::new(Mutex::new(node_inner)),
        }
    }

    pub fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{
        self.node_inner.clone().lock().unwrap().open_channel_negotiate(negotiate_message);
        Ok(())
    }

    pub fn open_channel(&self,open_channel_message:OpenChannelTransactionMessage)->Result<()>{
        self.node_inner.clone().lock().unwrap().open_channel(open_channel_message);
        Ok(())
    }

    pub fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        self.node_inner.clone().lock().unwrap().off_chain_pay(coin_resource_tag,receiver_address,amount);
        Ok(())
    }

    pub fn start_server(&self){
        let mut receiver =  self.node_inner.lock().unwrap().receiver.take().expect("receiver already taken");
        self.executor.spawn(Self::start(self.node_inner.clone(),receiver).boxed().unit_error().compat());
    }

    pub fn local_balance(&self)->Result<AccountResource>{
        let account_state_data=self.node_inner.clone().lock().unwrap().wallet.get_account_state();
        let account_state=AccountState::from_account_state_blob(account_state_data).unwrap().get_account_resource();
        match account_state {
            Some(state)=>Ok(state),
            None=>bail!("data is not ok")
        }
    }

    async fn start(node_inner:Arc<Mutex<NodeInner<C>>>,mut receiver:UnboundedReceiver<Message>){
        info!("start receive message");
        let mut receiver = receiver.compat();
        while let Some(message)=receiver.next().await{
            let data = bytes::Bytes::from(message.unwrap().msg);
            let msg_type=parse_message_type(&data);
            let node_inner=node_inner.lock().unwrap();
            match msg_type {
                MessageType::OpenChannelNodeNegotiateMessage => node_inner.handle_open_channel_negotiate(data[2..].to_vec()),
                MessageType::OpenChannelTransactionMessage => node_inner.handle_open_channel(data[2..].to_vec()),
                MessageType::OffChainPayMessage => node_inner.handle_off_chain_pay(data[2..].to_vec()),
                _=>warn!("message type not found {:?}",msg_type),
            };

        }
    }

}

impl<C: ChainClient+Send+Sync+'static> NodeInner<C>{

    fn send_message(&self,account_addr:&AccountAddress,msg:bytes::Bytes){
        let message = Message {
            peer_id:*account_addr,
            msg:msg.to_vec(),
        };
        self.sender.unbounded_send(message);
    }

    fn handle_open_channel_negotiate(&self,data:Vec<u8>){
        debug!("handle_open_channel_negotiate");
        let negotiate_message = OpenChannelNodeNegotiateMessage::from_proto_bytes(&data).unwrap();
        let raw_message = &(negotiate_message.raw_negotiate_message);
        if (raw_message.sender_addr == self.wallet.get_address()){
            match negotiate_message.receiver_sign {
                Some(sign)=>{
                    debug!("receive 2 sign");
                    // TODO send open channel msg
                },
                None=>debug!("none"),
            }
        }
        if (raw_message.receiver_addr == self.wallet.get_address()){
            // sign message ,verify messsage,send back
            debug!("receive sender neg msg")
        }
    }

    fn handle_open_channel(&self,data:Vec<u8>){
        debug!("handle_open_channel");
        let open_channel_message = OpenChannelTransactionMessage::from_proto_bytes(&data).unwrap();
        if (&open_channel_message.transaction.receiver() == &self.wallet.get_address()){
            // sign message ,verify messsage,send back
        }
        if (&open_channel_message.transaction.txn().sender() == &self.wallet.get_address()) {
            if (open_channel_message.transaction.output_signatures().len()==2){
                // wallet open channel
            }else {
                debug!("sign should eq 2");
            }
        }
    }

    fn handle_off_chain_pay(&self,data:Vec<u8>){ 
        debug!("off chain pay");
        let off_chain_pay_message = OffChainPayMessage::from_proto_bytes(&data).unwrap();
        let raw_transaction = off_chain_pay_message.transaction.borrow();
        let local_addr =self.wallet.get_address();
        if (&raw_transaction.receiver() == &local_addr){
            // sign message ,verify messsage, execute tx local
            self.wallet.apply_txn(raw_transaction).unwrap();
            let receiver_addr = &&raw_transaction.txn().sender(); //send to tx sender
            let off_chain_pay_message = OffChainPayMessage::new(raw_transaction.clone());
            let msg = add_message_type(off_chain_pay_message.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);
            self.send_message(receiver_addr,msg);
        }
        if (&raw_transaction.txn().sender() == &local_addr) {
            debug!("receive feed back pay");
            self.wallet.apply_txn(raw_transaction).unwrap();
            info!("tx succ");
        }
    }

    fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{  
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        let msg = add_message_type(msg, MessageType::OpenChannelNodeNegotiateMessage);
        self.send_message(&addr,msg);
        Ok(())
    }

    fn open_channel(&self,open_channel_message:OpenChannelTransactionMessage)->Result<()>{
        let addr = &open_channel_message.transaction.receiver();
        let msg = add_message_type(open_channel_message.into_proto_bytes()?, MessageType::OpenChannelTransactionMessage);
        self.send_message( addr,msg);
        Ok(())
    }

    fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        let off_chain_pay_tx = self.wallet.transfer(coin_resource_tag,receiver_address,amount)?;
        self.wallet.apply_txn(&off_chain_pay_tx)?;
        let off_chain_pay_msg = OffChainPayMessage {
            transaction:off_chain_pay_tx,
        };
        let msg = add_message_type(off_chain_pay_msg.into_proto_bytes()?, MessageType::OffChainPayMessage);
        self.send_message(&receiver_address ,msg);
        Ok(())
    }

}

fn parse_message_type(data:&bytes::Bytes)->MessageType{
    let data_slice = &data[0..2];
    let type_u16=u16::from_be_bytes([data_slice[0],data_slice[1]]);    
    MessageType::from_type(type_u16).unwrap()
}

fn add_message_type(data:Vec<u8>,messaget_type:MessageType)->bytes::Bytes{
    let len =u16::to_be_bytes(messaget_type.get_type());
    let mut result_vec = Vec::new();
    result_vec.extend_from_slice(&len);
    result_vec.extend_from_slice(&data);
    bytes::Bytes::from(result_vec)
}

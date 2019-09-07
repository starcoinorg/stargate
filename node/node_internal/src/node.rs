use tokio::{runtime::TaskExecutor};
use futures::{
    compat::{Stream01CompatExt,Compat01As03},
    future::{FutureExt},
    stream::{Stream,Fuse,StreamExt},
    prelude::*,
    executor::block_on,
};
use std::sync::{Arc,Mutex};
use sgwallet::wallet::Wallet;
use chain_client::{ChainClient};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::SigningKey;
use crypto::test_utils::KeyPair;
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes};
use types::account_address::AccountAddress;
use failure::prelude::*;
use std::{thread, time};
use logger::prelude::*;
use network::{
    {NetworkService, NetworkMessage}
};
use futures_01::sync::mpsc::{UnboundedSender,UnboundedReceiver};
use state_storage::AccountState;
use types::account_config::AccountResource;
use star_types::system_event::Event;
use types::language_storage::StructTag;
use futures_01::{future::Future, sync::oneshot,
                 sync::mpsc::{channel},
};
use crate::message_processor::{MessageProcessor,MessageFuture};
use crypto::hash::CryptoHash;


pub struct Node <C: ChainClient+Send+Sync+'static>{
    executor: TaskExecutor,
    node_inner:Arc<Mutex<NodeInner<C>>>,
    event_sender:UnboundedSender<Event>,
}

struct NodeInner<C: ChainClient+Send+Sync+'static> {
    wallet:Arc<Wallet<C>>,
    executor:TaskExecutor,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    network_service:NetworkService,
    network_service_close_tx: Option<oneshot::Sender<()>>,
    sender:UnboundedSender<NetworkMessage>,
    receiver:Option<UnboundedReceiver<NetworkMessage>>,
    event_receiver:Option<UnboundedReceiver<Event>>,
    message_processor:MessageProcessor,
}

impl<C:ChainClient+Send+Sync+'static> Node<C>{

    pub fn new(executor: TaskExecutor, wallet:Wallet<C>, keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
               mut network_service:NetworkService, sender:UnboundedSender<NetworkMessage>, receiver:UnboundedReceiver<NetworkMessage>) ->Self{
        let executor_clone = executor.clone();
        let net_close_tx= network_service.close_tx.take();
        let (event_sender, event_receiver) = futures_01::sync::mpsc::unbounded();

        let node_inner=NodeInner{
            executor:executor_clone,
            keypair,
            wallet:Arc::new(wallet),
            network_service,
            network_service_close_tx: net_close_tx,
            sender,
            receiver:Some(receiver),
            event_receiver:Some(event_receiver),
            message_processor:MessageProcessor::new(),
        };
        Self{
            executor,
            node_inner:Arc::new(Mutex::new(node_inner)),
            event_sender,
        }
    }

    pub fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{
        self.node_inner.clone().lock().unwrap().open_channel_negotiate(negotiate_message)
    }

    pub fn open_channel(&self,receiver: AccountAddress, sender_amount: u64, receiver_amount: u64)->Result<()>{
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.open(receiver,sender_amount,receiver_amount)?;
        let open_channel_message = ChannelTransactionMessage::new(channel_txn);
        self.node_inner.clone().lock().unwrap().channel_txn_onchain(open_channel_message,MessageType::ChannelTransactionMessage)
    }

    pub fn withdraw(&self,asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64)->Result<()>{
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.withdraw(asset_tag,receiver,sender_amount,receiver_amount)?;
        let open_channel_message = ChannelTransactionMessage::new(channel_txn);
        self.node_inner.clone().lock().unwrap().channel_txn_onchain(open_channel_message,MessageType::ChannelTransactionMessage)
    }

    pub fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        self.node_inner.clone().lock().unwrap().off_chain_pay(coin_resource_tag,receiver_address,amount)
    }

    pub fn start_server(&self){
        let receiver =  self.node_inner.lock().unwrap().receiver.take().expect("receiver already taken");
        let event_receiver = self.node_inner.lock().unwrap().event_receiver.take().expect("receiver already taken");
        self.executor.spawn(Self::start(self.node_inner.clone(),receiver,event_receiver).boxed().unit_error().compat());
    }

    pub fn local_balance(&self)->Result<AccountResource>{
        let account_state_data=self.node_inner.clone().lock().unwrap().wallet.get_account_state();
        let account_state=AccountState::from_account_state_blob(account_state_data).unwrap().get_account_resource();
        match account_state {
            Some(state)=>Ok(state),
            None=>bail!("data is not ok")
        }
    }

    pub fn channel_balance(&self,participant: AccountAddress, asset_tag: StructTag)->Result<u64>{
        self.node_inner.clone().lock().unwrap().wallet.channel_balance(participant,asset_tag)
    }

    pub fn shutdown(&self){
        debug!("node send shutdown event");
        self.event_sender.unbounded_send(Event::SHUTDOWN);
    }

    async fn start(node_inner:Arc<Mutex<NodeInner<C>>>, mut receiver:UnboundedReceiver<NetworkMessage>, mut event_receiver:UnboundedReceiver<Event>){
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
        let net_close_tx = node_inner.clone().lock().unwrap().network_service_close_tx.take();

        loop{
            futures::select! {
                message = receiver.select_next_some() => {
                    info!("receive message ");
                    let data = bytes::Bytes::from(message.unwrap().msg);
                    let msg_type=parse_message_type(&data);
                    let node_inner=node_inner.lock().unwrap();
                    match msg_type {
                        MessageType::OpenChannelNodeNegotiateMessage => node_inner.handle_open_channel_negotiate(data[2..].to_vec()),
                        MessageType::ChannelTransactionMessage => node_inner.handle_channel(data[2..].to_vec()),
                        MessageType::OffChainPayMessage => node_inner.handle_off_chain_pay(data[2..].to_vec()),
                        _=>warn!("message type not found {:?}",msg_type),
                    };
                },
                _ = event_receiver.select_next_some() => {
                    if let Some(sender) = net_close_tx{
                       debug!("To shutdown network");
                       let _ = sender.send(());
                    }
                    break;
                }
            }
        };
        info!("shutdown server listener");
    }

}

impl<C: ChainClient+Send+Sync+'static> NodeInner<C>{

    fn send_message(sender:UnboundedSender<NetworkMessage>, account_addr:&AccountAddress, msg:bytes::Bytes){
        let message = NetworkMessage {
            peer_id:*account_addr,
            msg:msg.to_vec(),
        };
        info!("send message ");
        sender.unbounded_send(message);
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

    fn handle_channel(&self,data:Vec<u8>){
        debug!("handle_open_channel");
        let open_channel_message = ChannelTransactionMessage::from_proto_bytes(&data).unwrap();
        if (&open_channel_message.transaction.receiver() == &self.wallet.get_address()){
            // sign message ,verify messsage,no send back
            let wallet = self.wallet.clone();
            let txn = &open_channel_message.transaction.clone();
            let f=async move {
                wallet.apply_txn(&txn).await;
            };
            f.boxed().unit_error().compat().wait();
        }
        if (&open_channel_message.transaction.txn().sender() == &self.wallet.get_address()) {
//            if (open_channel_message.transaction.output_signatures().len()==2){
//                // wallet open channel
//            }else {
//                debug!("sign should eq 2");
//            }
        }
    }

    fn handle_off_chain_pay(&self,data:Vec<u8>){
        debug!("off chain pay");
        let off_chain_pay_message = OffChainPayMessage::from_proto_bytes(&data).unwrap();
        let raw_transaction = off_chain_pay_message.transaction.clone();
        let local_addr =self.wallet.get_address();
        if (&raw_transaction.receiver() == &local_addr){
            // sign message ,verify messsage, execute tx local
            debug!("off chain txn as receiver");
            let wallet = self.wallet.clone();
            let sender = self.sender.clone();
            let raw_transaction = raw_transaction.clone();
            let f=async move {
                wallet.apply_txn(&raw_transaction).await;
                let receiver_addr = &&raw_transaction.txn().sender(); //send to tx sender
                let off_chain_pay_message = OffChainPayMessage::new(raw_transaction.clone());
                let msg = add_message_type(off_chain_pay_message.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);
                Self::send_message(sender,receiver_addr,msg);
            };
            f.boxed().unit_error().compat().wait();
        }
        if (&raw_transaction.txn().sender() == &local_addr) {
            debug!("receive feed back pay");
            /**
            let wallet = self.wallet.clone();
            let f=async move {
                wallet.apply_txn(&raw_transaction).await;
            };
            f.boxed().unit_error().compat().wait();*/
            info!("tx succ");
        }
    }

    fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        let msg = add_message_type(msg, MessageType::OpenChannelNodeNegotiateMessage);
        Self::send_message(self.sender.clone(),&addr,msg);
        Ok(())
    }

    fn channel_txn_onchain(&mut self,open_channel_message:ChannelTransactionMessage,msg_type:MessageType)->Result<()>{
        let sender = self.sender.clone();

        let hash_value = open_channel_message.transaction.clone().txn.into_raw_transaction().hash() ;
        let addr = &open_channel_message.transaction.receiver();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        Self::send_message(sender,addr,msg);

        let (tx,rx) =channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value,tx);
        message_future.wait();

        Ok(())
    }

    fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        let off_chain_pay_tx = self.wallet.transfer(coin_resource_tag,receiver_address,amount)?;
        let wallet = self.wallet.clone();
        let sender = self.sender.clone();
        let f= async move{
            wallet.apply_txn(&off_chain_pay_tx).await;
            let off_chain_pay_msg = OffChainPayMessage {
                transaction:off_chain_pay_tx,
            };
            let msg = add_message_type(off_chain_pay_msg.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);
            Self::send_message(sender,&receiver_address ,msg);
        };
        f.boxed().unit_error().compat().wait();

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

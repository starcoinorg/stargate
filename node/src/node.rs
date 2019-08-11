use switch::{switch::Switch};
use netcore::transport::{Transport};
use parity_multiaddr::Multiaddr;
use tokio::{codec::{Framed,LengthDelimitedCodec}, runtime::TaskExecutor};
use futures::{
    compat::{Sink01CompatExt,Stream01CompatExt,Compat01As03Sink,Compat01As03},
    future::{FutureExt},
    stream::{Stream,Fuse,StreamExt},
    io::{AsyncRead, AsyncWrite},
    prelude::*,
    sink::{SinkExt},
    channel::mpsc::{UnboundedReceiver,UnboundedSender},
};
use std::sync::{Arc,Mutex};
use sgwallet::wallet::Wallet;
use chain_client::{ChainClient};
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::SigningKey;
use nextgen_crypto::test_utils::KeyPair;
use tokio::sync::mpsc::{channel,Sender,Receiver};
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use std::collections::HashMap;
use types::account_address::AccountAddress;


pub struct Node <S:AsyncRead + AsyncWrite+Send+Sync+Unpin+'static,C: ChainClient>{
    executor: TaskExecutor,
    switch:Switch<S>,
    node_inner:Arc<Mutex<NodeInner<C>>>,
}

struct NodeInner<C: ChainClient> {
    wallet:Wallet<C>,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    sender_map:HashMap<AccountAddress,Sender<bytes::Bytes>>,
    //addr_map:HashMap<Multiaddr,Sender<bytes::Bytes>>,    
}

impl<S:AsyncRead + AsyncWrite+Send+Sync+Unpin+'static,C:ChainClient+Send+Sync+'static> Node<S,C>{

    pub fn new(executor: TaskExecutor,switch:Switch<S>,wallet:Wallet<C>,keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>)->Self{
        Self{
            executor,
            switch:switch,
            node_inner:Arc::new(Mutex::new(NodeInner{
                wallet,
                keypair,
                sender_map:HashMap::new(),
                //recv_map:HashMap::new(),
            })),
        }
    }

    pub fn start_server<T, L, I, E>(&self,
        transport: T,
        listen_addr: Multiaddr,
    ) -> Multiaddr where
    T: Transport<Output = S,Error = E, Listener = L, Inbound = I>,
    L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin + Send + 'static,
    I: Future<Output = Result<S, E>> + Send + 'static,
    E: ::std::error::Error + Send + Sync + 'static{
        let (listener, server_addr) = transport.listen_on(listen_addr).unwrap();

        let executor = self.executor.clone();
        self.executor.spawn(
            start_listen(listener,executor)
            .boxed()
            .unit_error()
            .compat(),
        );

        //self.handle_incomming(rx);
        server_addr
    }

    fn handle_incomming(&self,rx:Receiver<bytes::Bytes>,tx:Sender<bytes::Bytes>){
        let node_inner = self.node_inner.clone();
        let receive_future=async move{
            let mut rx = rx.compat();
            while let Some(Ok(data)) = rx.next().await {            
                let msg_type=parse_message_type(&data);
                 match msg_type {
                    MessageType::OpenChannelNodeNegotiateMessage => Self::handle_open_channel_negotiate(data[2..].to_vec(),node_inner.clone()),
                    MessageType::OpenChannelTransactionMessage => Self::handle_open_channel(data[2..].to_vec(),node_inner.clone()),
                    MessageType::OffChainPayMessage => Self::handle_off_chain_pay(data[2..].to_vec(),node_inner.clone()),
                    MessageType::AddressMessage => Self::handle_addr(data[2..].to_vec(),node_inner.clone()),                    
                };
             };            
        };
        self.executor.spawn(receive_future.boxed().unit_error().compat());
    }

    fn handle_open_channel_negotiate(data:Vec<u8>,node_data:Arc<Mutex<NodeInner<C>>>){
        let negotiate_message = OpenChannelNodeNegotiateMessage::from_proto_bytes(&data).unwrap();
        let raw_message = &(negotiate_message.raw_negotiate_message);
        if (raw_message.sender_addr == node_data.lock().unwrap().wallet.get_address()){
            match negotiate_message.receiver_sign {
                Some(sign)=>{
                    println!("sign");
                    // TODO send open channel msg
                },
                None=>println!("none"),
            }
        }
        if (raw_message.receiver_addr == node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back    
        }
    }

    fn handle_open_channel(data:Vec<u8>,node_data:Arc<Mutex<NodeInner<C>>>){
        let open_channel_message = OpenChannelTransactionMessage::from_proto_bytes(&data).unwrap();
        if (&open_channel_message.transaction.receiver() == &node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back    
        }
        if (&open_channel_message.transaction.txn().sender() == &node_data.lock().unwrap().wallet.get_address()) {
            if (open_channel_message.transaction.output_signatures().len()==2){
                // wallet open channel
            }else {
                println!("sign should eq 2");
            }
        }
    }

    fn handle_off_chain_pay(data:Vec<u8>,node_data:Arc<Mutex<NodeInner<C>>>){    
        let off_chain_pay_message = OffChainPayMessage::from_proto_bytes(&data).unwrap();
        if (off_chain_pay_message.transaction.receiver() == node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage, execute tx local
        }
    }

    fn handle_addr(data:Vec<u8>,node_data:Arc<Mutex<NodeInner<C>>>){    
    }

    pub fn connect<T, L, I, E,O>(&self,transport: T,addr: Multiaddr,remote_addr:AccountAddress)->Result<Sender<bytes::Bytes>,std::io::Error>
    where
        T: Transport<Output = S,Error = E, Listener = L, Inbound = I,Outbound= O>,
        L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin + Send + 'static,
        I: Future<Output = Result<S, E>> + Send + 'static,
        O: Future<Output = Result<S, E>> + Send + 'static,
        E: ::std::error::Error + Send + Sync + 'static{
            let (tx, rx) = channel(100);
            let outbound = transport.dial(addr).unwrap();        

            let local_addr=self.node_inner.clone().lock().unwrap().wallet.get_address().clone();
            let node_inner = self.node_inner.clone();
            let tx_clone = tx.clone();
            let dialer = async move {
                let mut socket = outbound.await.unwrap();

                let mut stream = Framed::new(socket.compat(), LengthDelimitedCodec::new()).sink_compat();
                let mut rx =  rx.compat();

                let addr_msg_bytes=AddressMessage::new(local_addr).into_proto_bytes().unwrap();                
                stream.send(bytes::Bytes::from(addr_msg_bytes)).await.unwrap();
                node_inner.lock().unwrap().sender_map.insert(remote_addr,tx_clone);
                
                while let Some(Ok(data)) = rx.next().await {
                    stream.send(data).await.unwrap();
                }
            };

            self.executor.spawn(dialer.boxed().unit_error().compat());
            Ok(tx.clone())
    }

    pub fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage){
        match self.node_inner.clone().lock().unwrap().sender_map.get(&negotiate_message.raw_negotiate_message.receiver_addr){
            Some(tx)=>{
                let msg=negotiate_message.into_proto_bytes().unwrap();
                self.send_message( tx,msg);
            }
            _ => println!("can't find sender by reciever address"),
        }
    }

    pub fn open_channel(&self,open_channel_message:OpenChannelTransactionMessage){
        match self.node_inner.clone().lock().unwrap().sender_map.get(&open_channel_message.transaction.receiver()){
            Some(tx)=>{
                let msg=open_channel_message.into_proto_bytes().unwrap();
                self.send_message( tx,msg);
            }
            _ => println!("can't find sender by reciever address"),
        }
    }

    pub fn send_message(&self,tx:&Sender<bytes::Bytes>,msg:Vec<u8>){
        let mut tx = tx.clone().sink_compat();
        let sender_future = async move{        
            tx.send(bytes::Bytes::from(msg)).await.unwrap();
        };
        self.executor.spawn(sender_future.boxed().unit_error().compat());
    }

    pub fn off_chain_pay(&self,off_chain_pay_message:OffChainPayMessage){
        match self.node_inner.clone().lock().unwrap().sender_map.get(&off_chain_pay_message.transaction.receiver()){
            Some(tx)=>{
                let msg=off_chain_pay_message.into_proto_bytes().unwrap();
                self.send_message( tx,msg);
            }
            _ => println!("can't find sender by reciever address"),
        }
    }

}

async fn start_listen<L, I, E,S>(mut server_listener: L,executor:TaskExecutor)
    where
        L: Stream<Item = Result<(I, Multiaddr), E>> +Unpin,
        I: Future<Output = Result<S, E>>+Send,
        S: AsyncRead + AsyncWrite +Send+Unpin+'static,
        E: ::std::error::Error, {
    while let Some(Ok((f_stream, _client_addr))) = server_listener.next().await {
        let stream = f_stream.await.unwrap();
        //let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new());

        //let (mut sink,stream) = Framed::new(f_stream, LengthDelimitedCodec::new()).split();
        
        //let mut tx_sink=tx.clone().sink_compat();

        //let (mut tx,rx) = channel(1000);
/*         let stream_compat = stream.compat();
        let mut stream_sink = Framed::new(stream_compat, LengthDelimitedCodec::new()).sink_compat();
        let mut tx_sink=tx.sink_compat();
        
        executor.spawn(handle_send(stream,tx).boxed().unit_error().compat());
        
        while let Some(Ok(data)) = stream_sink.next().await {            
            tx_sink.send(bytes::Bytes::from(data)).await;        
        }
        stream.close().await.unwrap();    
 */
        let (mut tx_h,  rx_h) = futures::channel::mpsc::unbounded();
        let (mut tx_g,  rx_g) = futures::channel::mpsc::unbounded();
        executor.spawn(handle_receive2(stream,tx_g,rx_h).boxed().unit_error().compat())
    }

}

async fn handle_receive<S>(stream:S,mut tx:Sender<bytes::Bytes>)
where S: AsyncRead + AsyncWrite +Send+Unpin+'static,{    
    let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new()).sink_compat();
    let mut tx_sink=tx.sink_compat();
    while let Some(Ok(data)) = stream.next().await {            
        tx_sink.send(bytes::Bytes::from(data)).await;        
    }
    stream.close().await.unwrap();    
}

async fn handle_receive2<S>(stream:S,mut tx:UnboundedSender<bytes::Bytes>,mut rx:UnboundedReceiver<bytes::Bytes>)
where S: AsyncRead + AsyncWrite +Send+Unpin+'static,{    
    let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new()).sink_compat().fuse();
    //let mut tx_sink=tx.sink_compat();
    loop {
        futures::select! {
            data=stream.select_next_some()=>{
                println!("{:?}",data);
                let data = data.unwrap();
                tx.unbounded_send(bytes::Bytes::from(data));
                //tx.clone().unbounded_send(data);
            },
            data=rx.select_next_some()=>{
                println!("{:?}",data);
                stream.send(data).await.unwrap();
            },
        }
    }
    stream.close().await.unwrap();    
}

/* async fn handle_send<S>(stream:Compat01As03<S>,mut rx:Sender<bytes::Bytes>)
where S: AsyncRead + AsyncWrite +Send+Unpin+'static,{    
    //let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new()).sink_compat();
    //let mut tx_sink=tx.sink_compat();
    while let Some(Ok(data)) = stream.next().await {            
        //tx_sink.send(bytes::Bytes::from(data)).await;        
    }
    stream.close().await.unwrap();    
}
 */
fn parse_message_type(data:&bytes::Bytes)->MessageType{
    let data_slice = &data[0..2];
    let type_u16=u16::from_be_bytes([data_slice[0],data_slice[1]]);
    MessageType::from_type(type_u16).unwrap()
}

fn add_message_type(data:bytes::Bytes,messaget_type:MessageType)->bytes::Bytes{
    let len =u16::to_be_bytes(messaget_type.get_type());
    let mut result_vec = Vec::new();
    result_vec.extend_from_slice(&len);
    result_vec.extend_from_slice(&data[..]);
    bytes::Bytes::from(result_vec)
}
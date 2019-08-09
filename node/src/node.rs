use switch::{switch::Switch};
use netcore::transport::{Transport};
use parity_multiaddr::Multiaddr;
use tokio::{codec::{Framed,LengthDelimitedCodec}, runtime::TaskExecutor};
use futures::{
    compat::{Sink01CompatExt,Stream01CompatExt,Compat01As03Sink},
    future::{FutureExt},
    stream::Stream,
    io::{AsyncRead, AsyncWrite},
    prelude::*,
    sink::{SinkExt},
};
use std::sync::Arc;
use sgwallet::wallet::Wallet;
use chain_client::{ChainClient};
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::SigningKey;
use nextgen_crypto::test_utils::KeyPair;
use tokio::sync::mpsc::{channel,Sender,Receiver};
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use std::collections::HashMap;

pub struct Node <S:AsyncRead + AsyncWrite+Send+Sync+Unpin+'static,C: ChainClient>{
    switch:Switch<S>,
    wallet:Wallet<C>,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    send_map:HashMap<Multiaddr,S>,
    recv_map:HashMap<Multiaddr,S>,
}

impl<S:AsyncRead + AsyncWrite+Send+Sync+Unpin+'static,C:ChainClient> Node<S,C>{

    pub fn new(switch:Switch<S>,wallet:Wallet<C>,keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>)->Self{
        Self{
            switch:switch,
            wallet,keypair,
            send_map:HashMap::new(),
            recv_map:HashMap::new(),
        }
    }

    pub fn start_server<T, L, I, E>(self,
        executor: &TaskExecutor,
        transport: T,
        listen_addr: Multiaddr,
    ) -> Multiaddr where
    T: Transport<Output = S,Error = E, Listener = L, Inbound = I>,
    L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin + Send + 'static,
    I: Future<Output = Result<S, E>> + Send + 'static,
    E: ::std::error::Error + Send + Sync + 'static{
        let (listener, server_addr) = transport.listen_on(listen_addr).unwrap();
        let (tx, rx) = channel(100);
        executor.spawn(
            start_listen(listener,tx)
            .boxed()
            .unit_error()
            .compat(),
        );

        let executor=executor.clone();
        self.handle_incomming(&executor,rx);
        server_addr
    }

    fn handle_incomming(self,executor: &TaskExecutor,rx:Receiver<bytes::Bytes>){
        let mut rx = rx.compat();
        let receive_future=async move{
            while let Some(Ok(data)) = rx.next().await {            

            }            
        };
        executor.spawn(receive_future.boxed().unit_error().compat());
    }

    pub fn connect<T, L, I, E,O>(self,executor: &TaskExecutor,transport: T,addr: Multiaddr)->Result<Sender<bytes::Bytes>,std::io::Error>
    where
        T: Transport<Output = S,Error = E, Listener = L, Inbound = I,Outbound= O>,
        L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin + Send + 'static,
        I: Future<Output = Result<S, E>> + Send + 'static,
        O: Future<Output = Result<S, E>> + Send + 'static,
        E: ::std::error::Error + Send + Sync + 'static{
            let (tx, rx) = channel(100);
            let outbound = transport.dial(addr).unwrap();

            let dialer = async move {
                let mut socket = outbound.await.unwrap();
                let mut stream = Framed::new(socket.compat(), LengthDelimitedCodec::new()).sink_compat();
                let mut rx =  rx.compat();

                while let Some(Ok(data)) = rx.next().await {
                    stream.send(data).await.unwrap();
                }
            };

            executor.spawn(dialer.boxed().unit_error().compat());
            Ok(tx)
    }

    pub fn open_channel_negotiate(self,executor: &TaskExecutor,tx:Sender<bytes::Bytes>,negotiate_message:OpenChannelNodeNegotiateMessage){
        let msg=negotiate_message.into_proto_bytes().unwrap();
        self.send_message(executor, tx,msg);
    }

    pub fn open_channel(self,executor: &TaskExecutor,tx:Sender<bytes::Bytes>,open_channel_message:OpenChannelTransactionMessage){
        let msg=open_channel_message.into_proto_bytes().unwrap();
        self.send_message(executor, tx,msg);
    }

    pub fn send_message(self,executor: &TaskExecutor,tx:Sender<bytes::Bytes>,msg:Vec<u8>){
        let mut tx = tx.clone().sink_compat();
        let sender_future = async move{        
            tx.send(bytes::Bytes::from(msg)).await.unwrap();
        };
        executor.spawn(sender_future.boxed().unit_error().compat());
    }

    pub fn off_chain_pay(self,executor: &TaskExecutor,tx:Sender<bytes::Bytes>,pay_message:OffChainPayMessage){
        let msg=pay_message.into_proto_bytes().unwrap();
        self.send_message(executor, tx,msg);
    }

}

async fn start_listen<L, I, E,S>(mut server_listener: L,tx:Sender<bytes::Bytes>)
    where
        L: Stream<Item = Result<(I, Multiaddr), E>> +Unpin,
        I: Future<Output = Result<S, E>>,
        S: AsyncRead + AsyncWrite +Send+Unpin,
        E: ::std::error::Error, {
    while let Some(Ok((f_stream, _client_addr))) = server_listener.next().await {
        let stream = f_stream.await.unwrap();
        let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new()).sink_compat();

        let mut tx_sink=tx.clone().sink_compat();
        while let Some(Ok(data)) = stream.next().await {            
            tx_sink.send(bytes::Bytes::from(data)).await;
        }
        stream.close().await.unwrap();
    }

}

async fn parse_message_type(data:bytes::Bytes){

}
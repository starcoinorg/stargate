use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use futures::{
    Future,Poll,Async,Stream,
    sync::mpsc::{Receiver,Sender},
    sink::Sink,
};

use crypto::{
    HashValue,
};
use star_types::{proto::{chain::{ WatchTransactionResponse}}};
use logger::prelude::*;
use failure::prelude::*;
use proto_conv::{FromProto};
use types::transaction::{ SignedTransaction};
use crypto::hash::CryptoHash;
use tokio::{runtime::TaskExecutor};
use chain_client::{ChainClient};
use types::account_address::AccountAddress;


pub struct SubmitTransactionFuture {
    rx:Receiver<WatchTransactionResponse>,
    tx_resp:Option<WatchTransactionResponse>,
}

impl SubmitTransactionFuture {
    pub fn new(rx:Receiver<WatchTransactionResponse>) -> SubmitTransactionFuture {
        Self{
            rx,
            tx_resp:None,
        }
    }

    pub fn get_response(&self)->Option<&WatchTransactionResponse> {
        self.tx_resp.as_ref()
    }

}

impl Future for SubmitTransactionFuture {
    type Item = ();
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        while let Async::Ready(v) = self.rx.poll().unwrap() {
            match v {
                Some(v) => {
                    self.tx_resp = Some(v);
                    break;
                }
                None => {
                    debug!("no data");
                    break;
                }
            }
        }

        Ok(Async::Ready(()))
    }
}

pub struct TransactionProcessor {
    tx_map:HashMap<HashValue,Sender<WatchTransactionResponse>>,
}

impl TransactionProcessor {

    pub fn new() -> Self {
        Self{
            tx_map:HashMap::new()
        }
    }

    pub fn add_future(& mut self,hash:HashValue,sender:Sender<WatchTransactionResponse>){
        self.tx_map.entry(hash).or_insert(sender);
    }

    pub fn send_response(&self,mut resp:WatchTransactionResponse)->Result<()> {
        let txn=SignedTransaction::from_proto(resp.take_signed_txn())?;
        let  hash = txn.hash();
        match self.tx_map.get(&hash) {
            Some(tx) => {tx.clone().send(resp);},
            _ => info!("tx hash {} not in map",hash) ,
        }
        Ok(())
    }

}

pub fn start_processor<C>(client:Arc<C>,addr:AccountAddress)->Result<()>
where C: ChainClient+Sync+Send+'static{
    let read_stream_future = move || {
        let tx_stream=client.watch_transaction(&addr,0).unwrap();

        let f = tx_stream.for_each(|item| {
            println!("received sign {:?}", item);
            Ok(())
        });
        f.wait().unwrap();
    };

    thread::spawn(read_stream_future);

    Ok(())
}

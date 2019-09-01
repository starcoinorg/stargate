use std::collections::HashMap;
use std::sync::{Arc,Mutex};
use std::thread;

use futures::{
    Future,Poll,Async,Stream,
    sync::mpsc::{Receiver,Sender},
    sink::Sink,
};

use crypto::{
    HashValue,
};
use logger::prelude::*;
use failure::prelude::*;
use types::transaction::{ SignedTransaction};
use crypto::hash::CryptoHash;
use chain_client::{ChainClient};
use types::account_address::AccountAddress;


pub struct SubmitTransactionFuture {
    rx:Receiver<SignedTransaction>,
}

impl SubmitTransactionFuture {
    pub fn new(rx:Receiver<SignedTransaction>) -> SubmitTransactionFuture {
        Self{
            rx,
        }
    }

}

impl Future for SubmitTransactionFuture {
    type Item = SignedTransaction;
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<SignedTransaction, Self::Error> {
        while let Async::Ready(v) = self.rx.poll().unwrap() {
            match v {
                Some(v) => {
                    return Ok(Async::Ready(v));
                }
                None => {
                    debug!("no data");
                    return Ok(Async::NotReady);
                }
            }
        };
        return Ok(Async::NotReady);
    }
}

pub struct TransactionProcessor {
    tx_map:HashMap<HashValue,Sender<SignedTransaction>>,
}

impl TransactionProcessor {

    pub fn new() -> Self {
        Self{
            tx_map:HashMap::new()
        }
    }

    pub fn add_future(& mut self,hash:HashValue,sender:Sender<SignedTransaction>){
        self.tx_map.entry(hash).or_insert(sender);
    }

    pub fn send_response(&self,mut txn:SignedTransaction)->Result<()> {
        let  hash = txn.hash();
        match self.tx_map.get(&hash) {
            Some(tx) => {tx.clone().send(txn);},
            _ => info!("tx hash {} not in map",hash) ,
        }
        Ok(())
    }

}

pub fn start_processor<C>(client:Arc<C>,addr:AccountAddress,processor:Arc<Mutex<TransactionProcessor>>)->Result<()>
where C: ChainClient+Sync+Send+'static{
    let read_stream_thread = move || {
        let tx_stream=client.watch_transaction(&addr,0).unwrap();

        let f = tx_stream.for_each(|item| {
            info!("received sign {:?}", item);
            processor.lock().unwrap().send_response(item).unwrap();
            Ok(())
        });
        f.wait().unwrap();
    };

    thread::spawn(read_stream_thread);

    Ok(())
}

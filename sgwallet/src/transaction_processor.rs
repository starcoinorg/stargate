use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use futures::{
    Future, Poll, Async, Stream,
    sync::mpsc::{Receiver, Sender},
    sink::Sink,
};

use crypto::HashValue;
use logger::prelude::*;
use failure::prelude::*;
use types::transaction::{SignedTransaction, TransactionOutput};
use crypto::hash::CryptoHash;
use chain_client::{ChainClient, watch_stream::WatchResp};
use types::account_address::AccountAddress;
use star_types::watch_tx_data::WatchTxData;
use atomic_refcell::AtomicRefCell;


pub struct SubmitTransactionFuture {
    rx: Receiver<(SignedTransaction,TransactionOutput)>,
}

impl SubmitTransactionFuture {
    pub fn new(rx: Receiver<(SignedTransaction,TransactionOutput)>) -> SubmitTransactionFuture {
        Self {
            rx,
        }
    }
}

impl Future for SubmitTransactionFuture {
    type Item = (SignedTransaction,TransactionOutput);
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Async::Ready(v) = self.rx.poll().unwrap() {
            match v {
                Some(v) => {
                    info!("tx is {}, output: {}", v.0.raw_txn().hash(), &v.1);
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
    tx_map: HashMap<HashValue, Sender<(SignedTransaction,TransactionOutput)>>,
    //TODO limit cache size.
    tx_cache: Arc<AtomicRefCell<HashMap<HashValue, (SignedTransaction,TransactionOutput)>>>,
}

impl TransactionProcessor {
    pub fn new() -> Self {
        Self {
            tx_map: HashMap::new(),
            tx_cache: Arc::new(AtomicRefCell::new(HashMap::new())),
        }
    }

    pub fn add_future(&mut self, hash: HashValue, sender: Sender<(SignedTransaction,TransactionOutput)>){
        match self.tx_cache.borrow().get(&hash){
            // if result exist, complete the feature
            Some(result) => {
                match sender.send(result.clone()).wait() {
                    Ok(_) => info!("send message succ"),
                    //TODO raise error?
                    Err(_) => warn!("send message error"),
                }
            }
            None => {
                self.tx_map.entry(hash).or_insert(sender);
            }
        }
    }

    pub fn send_response(&self, watch_data: (SignedTransaction,TransactionOutput)) -> Result<()> {
        let hash = watch_data.0.raw_txn().hash();
        self.tx_cache.borrow_mut().insert(hash.clone(), watch_data.clone());
        match self.tx_map.get(&hash) {
            Some(sender) => {
                match sender.clone().send(watch_data).wait() {
                    Ok(_new_tx) => info!("send message succ"),
                    Err(_) => warn!("send message error"),
                };
            }
            _ => info!("tx hash {} not in map", hash),
        }
        Ok(())
    }
}

pub fn start_processor<C>(client: Arc<C>, addr: AccountAddress, processor: Arc<Mutex<TransactionProcessor>>) -> Result<()>
    where C: ChainClient + Sync + Send + 'static {
    let read_stream_thread = move || {
        let tx_stream = client.watch_transaction(&addr, 0).unwrap();

        let f = tx_stream.for_each(|item| {
            match item {
                WatchResp::TX(data) => {
                    let WatchTxData{signed_tx, output } = data;
                    debug!("process tx:{}, output:{}", signed_tx.raw_txn().hash(), output);
                    processor.lock().unwrap().send_response((signed_tx,output)).unwrap();
                }
                _ => { format_err!("err type"); }
            };

            Ok(())
        });
        f.wait().unwrap();
    };

    thread::spawn(read_stream_thread);

    Ok(())
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use futures_01::{
    Future, Poll, Async, Stream,
    sync::mpsc::{Receiver, Sender},
    sink::Sink,
};

use crypto::HashValue;
use logger::prelude::*;
use failure::prelude::*;
use crypto::hash::CryptoHash;
use network::NetworkMessage;
use star_types::channel_transaction::ChannelTransaction;
use tokio::{runtime::TaskExecutor};

pub struct MessageFuture {
    rx: Receiver<ChannelTransaction>,
}

impl MessageFuture {
    pub fn new(rx: Receiver<ChannelTransaction>) -> Self {
        Self {
            rx,
        }
    }
}

impl Future for MessageFuture {
    type Item = ChannelTransaction;
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<ChannelTransaction, Self::Error> {
        while let Async::Ready(v) = self.rx.poll().unwrap() {
            match v {
                Some(v) => {
                    return Ok(Async::Ready(v));
                }
                None => {
                    warn!("no data,return timeout");
                    return Err(Self::Error::new(std::io::ErrorKind::TimedOut,"future time out"));
                }
            }
        };
        return Ok(Async::NotReady);
    }
}

#[derive(Clone)]
pub struct MessageProcessor {
    tx_map: Arc<Mutex<HashMap<HashValue, Sender<ChannelTransaction>>>>,
}

impl MessageProcessor {
    pub fn new() -> Self {
        Self {
            tx_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_future(&self, hash: HashValue, mut sender: Sender<ChannelTransaction>) {
        self.tx_map.lock().unwrap().entry(hash).or_insert(sender.clone());
    }

    pub fn send_response(&mut self, mut msg: ChannelTransaction) -> Result<()> {
        let hash = msg.txn.clone().into_raw_transaction().hash();

        let mut tx_map= self.tx_map.lock().unwrap();
        match tx_map.get(&hash) {
            Some(tx) => {
                match tx.clone().send(msg).wait() {
                    Ok(_new_tx) => {
                        info!("send message succ");
                        tx_map.remove(&hash);
                    },
                    Err(_) => warn!("send message error"),
                };
            }
            _ => info!("tx hash {} not in map", hash),
        }
        Ok(())
    }

    pub fn remove_future(&self, hash: HashValue){
        self.tx_map.lock().unwrap().remove(&hash);
    }
}

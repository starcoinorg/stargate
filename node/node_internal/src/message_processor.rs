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
                    warn!("tx is {:?}", v);
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

pub struct MessageProcessor {
    tx_map: HashMap<HashValue, Sender<ChannelTransaction>>,
}

impl MessageProcessor {
    pub fn new() -> Self {
        Self {
            tx_map: HashMap::new()
        }
    }

    pub fn add_future(&mut self, hash: HashValue, sender: Sender<ChannelTransaction>) {
        self.tx_map.entry(hash).or_insert(sender);
    }

    pub fn send_response(&mut self, mut msg: ChannelTransaction) -> Result<()> {
        let hash = msg.txn.clone().into_raw_transaction().hash();

        match self.tx_map.get(&hash) {
            Some(tx) => {
                match tx.clone().send(msg).wait() {
                    Ok(_new_tx) => {
                        info!("send message succ");
                        self.tx_map.remove(&hash);
                    },
                    Err(_) => warn!("send message error"),
                };
            }
            _ => info!("tx hash {} not in map", hash),
        }
        Ok(())
    }
}

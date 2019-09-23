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
use star_types::channel_transaction::ChannelTransactionRequest;
use tokio::{runtime::TaskExecutor};
use star_types::message::{SgError, ErrorMessage};
use futures::future::err;

pub struct MessageFuture {
    rx: Receiver<Result<()>>,
}

impl MessageFuture {
    pub fn new(rx: Receiver<Result<()>>) -> Self {
        Self {
            rx,
        }
    }
}

impl Future for MessageFuture {
    type Item = ();
    type Error = SgError;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        while let Async::Ready(v) = self.rx.poll().unwrap() {
            match v {
                Some(v) => {
                    match v {
                        Ok(v)=>{
                            return Ok(Async::Ready(v));
                        },
                        Err(e)=>{
                            return Err(error_translate(e));
                        }
                    }
                }
                None => {
                    warn!("no data,return timeout");
                    return Err(Self::Error::new(star_types::sg_error::SgErrorCode::TIMEOUT,"future time out".to_string()));
                }
            }
        };
        return Ok(Async::NotReady);
    }
}

#[derive(Clone)]
pub struct MessageProcessor {
    tx_map: Arc<Mutex<HashMap<HashValue, Sender<Result<()>>>>>,
}

impl MessageProcessor {
    pub fn new() -> Self {
        Self {
            tx_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_future(&self, hash: HashValue, mut sender: Sender<Result<()>>) {
        self.tx_map.lock().unwrap().entry(hash).or_insert(sender.clone());
    }

    pub fn send_response(&mut self, mut hash: HashValue) -> Result<()> {

        let mut tx_map= self.tx_map.lock().unwrap();
        match tx_map.get(&hash) {
            Some(tx) => {
                match tx.clone().send(Ok(())).wait() {
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
        let mut tx_map= self.tx_map.lock().unwrap();
        match tx_map.get(&hash) {
            Some(tx) => {
                info!("future time out,hash is {:?}",hash);
                tx_map.remove(&hash);
            }
            _ => info!("tx hash {} not in map,timeout is not necessary", hash),
        }
    }

    pub fn future_error(&self, error_msg:ErrorMessage){
        let mut tx_map= self.tx_map.lock().unwrap();
        match tx_map.get(&error_msg.raw_transaction_hash) {
            Some(tx) => {
                tx.clone().send(Err(error_msg.error.into())).wait();
                tx_map.remove(&error_msg.raw_transaction_hash);
            }
            _ => info!("tx hash {} not in map,error is not necessary", error_msg.raw_transaction_hash),
        }
    }

}

fn error_translate(e:Error)->SgError{
    let error_message :ErrorMessage;
    if let Some(err) = e.downcast_ref::<SgError>() {
        info!("this is a sg error");
        err.clone()
    } else {
        info!("this is a common error");
        SgError::new(star_types::sg_error::SgErrorCode::UNKNOWN,format!("{:?}", e))
    }
}
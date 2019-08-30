use futures_01::{
    Future,Poll,Async
};

use crypto::{
    HashValue,
};
use star_types::{proto::{chain::{ WatchTransactionResponse}}};

pub struct SubmitTransactionFuture {
    tx_hash:HashValue,
    tx_resp:Option<WatchTransactionResponse>,
}

impl SubmitTransactionFuture {
    pub fn new(tx_hash:HashValue) -> SubmitTransactionFuture {
        Self{
            tx_hash,
            tx_resp:None,
        }
    }
}

impl Future for SubmitTransactionFuture {
    type Item = ();
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        Ok(Async::NotReady)
    }
}

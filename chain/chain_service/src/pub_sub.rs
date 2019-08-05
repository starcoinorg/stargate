extern crate grpcio;

use std::sync::{mpsc, Arc, Mutex};
use std::collections::HashMap;
use std::time;
use types::proto::transaction::TransactionToCommit;
use std::sync::Once;
use std::mem::transmute;
use core::borrow::Borrow;
use futures::sync::mpsc::{unbounded, UnboundedSender, UnboundedReceiver, SendError};
use futures::{stream::Stream, Poll};
use grpcio::WriteFlags;
use core::pin::Pin;
use core::task::Context;
use chain_proto::proto::chain::WatchTransactionResponse;

#[derive(Clone)]
struct Pub {
    senders: Arc<Mutex<HashMap<String, UnboundedSender<WatchTransactionResponse>>>>,
}

fn singleton() -> Pub {
    static mut SINGLETON: *const Pub = 0 as *const Pub;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = Pub {
                senders: Arc::new(Mutex::new(HashMap::<String, UnboundedSender<WatchTransactionResponse>>::new())),
            };

            SINGLETON = transmute(Box::new(singleton));
        });

        (*SINGLETON).clone()
    }
}

pub fn send(tx: WatchTransactionResponse) -> Result<(), SendError<WatchTransactionResponse>> {
    let p = singleton();
    let senders = p.senders.lock().unwrap();
    println!("{}:{}", "---------8888888--------", senders.len());
    for (_, sender) in senders.iter() {
        println!("{}", "---------999999999--------");
        match sender.unbounded_send(tx.clone()) {
            Ok(_) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

pub fn subscribe(id: String, sender: UnboundedSender<WatchTransactionResponse>) {
    let p = singleton();
    let mut senders = p.senders.lock().unwrap();
    senders.insert(id, sender);
}

pub fn unsubscribe(id: String) {
    let p = singleton();
    let mut senders = p.senders.lock().unwrap();
    senders.remove(&id);
}


#[cfg(test)]
mod tests {

    #[test]
    fn test_xxx() {

    }
}
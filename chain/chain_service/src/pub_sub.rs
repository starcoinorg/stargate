use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::sync::Once;
use std::mem::transmute;
use futures::sync::mpsc::{UnboundedSender, SendError};
use star_types::proto::chain::WatchTransactionResponse;

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
    for (_, sender) in senders.iter() {
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
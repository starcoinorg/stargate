use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use futures::sync::mpsc::{UnboundedSender, SendError};
use crypto::HashValue;

struct WatchInner<T> where T: Clone {
    sender: UnboundedSender<T>,
    filter_func: Box<dyn Fn(T) -> bool + Send>,
}

#[derive(Clone)]
pub struct Pub<T> where T: Clone {
    senders: Arc<Mutex<HashMap<HashValue, WatchInner<T>>>>,
}

impl<T> Pub<T> where T: Clone {
    pub fn new() -> Self {
        Pub {
            senders: Arc::new(Mutex::new(HashMap::<HashValue, WatchInner<T>>::new())),
        }
    }

    pub fn send(&self, tx: T) -> Result<(), SendError<T>> {
        let senders = self.senders.lock().unwrap();
        for (id, inner) in senders.iter() {
            let func = &inner.filter_func;
            let send_flag = (func)(tx.clone());
            if send_flag {
                match inner.sender.unbounded_send(tx.clone()) {
                    Ok(_) => {}
                    Err(err) => return {
                        self.unsubscribe(id);
                        Err(err)
                    },
                }
            }
        }

        Ok(())
    }

    pub fn subscribe(&self, id: HashValue, sender: UnboundedSender<T>, filter: Box<dyn Fn(T) -> bool + Send>) {
        let mut senders = self.senders.lock().unwrap();
        senders.insert(id, WatchInner { sender, filter_func: filter });
    }

    pub fn unsubscribe(&self, id: &HashValue) {
        let mut senders = self.senders.lock().unwrap();
        senders.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use crate::pub_sub::Pub;

    #[test]
    fn test_pub_new() {
        let pub_new = Pub::<u64>::new();
        println!("{}", "?????");
    }
}

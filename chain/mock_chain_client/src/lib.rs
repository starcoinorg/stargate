use failure::prelude::*;
use chain_service::chain_service::ChainService;
use chain_client::{ChainClient, watch_stream::WatchStream};
use crypto::HashValue;
use tokio::runtime::TaskExecutor;
use logger::prelude::*;
use types::{event::EventKey, account_address::AccountAddress, access_path::AccessPath, transaction::{SignedTransaction, Version}};
use futures::{
    sync::mpsc::UnboundedReceiver,
    Stream, Poll,
};
use star_types::{proto::{chain::{WatchData}}, channel_transaction::ChannelTransaction};
use atomic_refcell::{AtomicRefCell};
use std::sync::Arc;
use core::borrow::{BorrowMut};
use std::sync::mpsc;

#[derive(Clone)]
pub struct MockChainClient {
    //exe: TaskExecutor,
    chain_service: Arc<AtomicRefCell<ChainService>>,
}

impl MockChainClient {
    pub fn new(exe: TaskExecutor) -> (Self, mpsc::Receiver<()>) {
        let (chain_service, receiver) = ChainService::new(&exe, &Some("/tmp/data".to_string()));
        let client = Self {
            //exe,
            chain_service: Arc::new(AtomicRefCell::new(chain_service)),
        };
        (client, receiver)
    }

}

pub struct MockStreamReceiver<T> {
    inner_rx: UnboundedReceiver<T>
}

impl<T> Stream for MockStreamReceiver<T> {
    type Item = T;
    type Error = grpcio::Error;

    fn poll(&mut self) -> Poll<Option<T>, Self::Error> {
        self.inner_rx.poll().map_err(|e| { grpcio::Error::RemoteStopped })
    }
}

impl ChainClient for MockChainClient {
    type WatchResp = MockStreamReceiver<WatchData>;

    fn latest_state_root(&self) -> Result<HashValue> {
        let chain_service = self.chain_service.as_ref().borrow();
        Ok(chain_service.latest_state_root_inner())
    }

    fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        let chain_service = self.chain_service.as_ref().borrow();
        let account = chain_service.get_account_state_with_proof_inner(address, None).unwrap().1;
        let blob = match account {
            Some(a) => { Some(a.as_ref().to_vec()) }
            None => { None }
        };
        Ok(blob)
    }

    fn get_state_by_access_path(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        debug!("get_state_by_access_path:{}", access_path);
        let chain_service = self.chain_service.as_ref().borrow();
        chain_service.state_by_access_path_inner(access_path.address, access_path.path.clone())
    }

    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()> {
        let chain_service = self.chain_service.as_ref().borrow();
        chain_service.faucet_inner(address, amount).map(|_| ())
    }

    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
        let chain_service = self.chain_service.as_ref().borrow();
        chain_service.send_tx(signed_transaction);

        Ok(())
    }

    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchStream<Self::WatchResp>> {
        let chain_service = self.chain_service.as_ref().borrow();
        let rx = chain_service.watch_transaction_inner(*address, ver);
        let stream = MockStreamReceiver { inner_rx: rx };
        Ok(WatchStream::new(stream))
    }

    fn watch_event(&self, _address: &AccountAddress, _event_keys: Vec<EventKey>) -> Result<WatchStream<Self::WatchResp>> {
        unimplemented!()
    }

    fn get_transaction_by_ver(&self, ver: Version) -> Result<SignedTransaction> {
        let chain_service = self.chain_service.as_ref().borrow();
        chain_service.get_transaction_by_ver(ver)
    }

    fn get_transaction_by_seq_num(&self, address: &AccountAddress, seq_num: u64) -> Result<SignedTransaction> {
        let chain_service = self.chain_service.as_ref().borrow();
        chain_service.get_transaction_by_seq_num_inner(address.clone(), seq_num)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_mock_client() {
        let rt = Runtime::new().unwrap();
        let (client,_) = MockChainClient::new(rt.executor());
        let state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state)
    }

    #[test]
    fn test_mock_faucet() {
        let rt = Runtime::new().unwrap();
        let (client,_) = MockChainClient::new(rt.executor());
        let mut state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state);
        let receiver = AccountAddress::random();
        client.faucet(receiver, 100);
        client.faucet(receiver, 100);
        state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state);
    }

    #[test]
    fn test_test() {
        let mut rt1 = Runtime::new().unwrap();
        let (mock_chain_service, db_shutdown_receiver) = MockChainClient::new(rt1.executor());
        let client=Arc::new(mock_chain_service);
        let mut state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state);
        let receiver = AccountAddress::random();
        client.faucet(receiver, 100);
        client.faucet(receiver, 100);
        state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state);
    }
}

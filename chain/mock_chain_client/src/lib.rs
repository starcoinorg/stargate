use failure::prelude::*;
use chain_service::chain_service::{ChainService, TransactionInner};
use chain_client::{ChainClient, watch_transaction_stream::WatchTransactionStream};
use crypto::HashValue;
use tokio::runtime::TaskExecutor;
use logger::prelude::*;
use types::{event::EventKey, account_address::AccountAddress, access_path::AccessPath, transaction::{SignedTransaction, Version}};
use futures03::{
    executor::block_on,
};
use futures::{
    sync::mpsc::UnboundedReceiver,
    Stream, Poll,
};
use star_types::{proto::{chain::WatchTransactionResponse}};


#[derive(Clone)]
pub struct MockChainClient {
    exe: TaskExecutor,
    chain_service: Option<ChainService>,
}

impl MockChainClient {
    pub fn new(exe: TaskExecutor) -> Self {
        let mut client = Self {
            exe,
            chain_service: None,
        };
        client.init();
        client
    }

    fn init(&mut self) {
        self.chain_service = Some(ChainService::new(&self.exe))
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
    type WatchResp = MockStreamReceiver<WatchTransactionResponse>;


    fn least_state_root(&self) -> Result<HashValue> {
        Ok(self.chain_service.as_ref().unwrap().least_state_root_inner())
    }

    fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_service.as_ref().unwrap().get_account_state_with_proof_by_state_root_inner(*address))
    }

    fn get_state_by_access_path(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        debug!("get_state_by_access_path:{}", access_path);
        self.chain_service.as_ref().unwrap().state_by_access_path_inner(access_path.address, access_path.path.clone())
    }

    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()> {
        self.chain_service.as_ref().unwrap().faucet_inner(address, amount).map(|_| ())
    }

    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
        let chain_service = self.chain_service.as_ref().unwrap();
        block_on(chain_service.submit_transaction_inner(chain_service.sender(), TransactionInner::OnChain(signed_transaction)));

        Ok(())
    }

    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchTransactionStream<Self::WatchResp>> {
        let rx = self.chain_service.as_ref().unwrap().watch_transaction_inner(*address, ver);
        let stream = MockStreamReceiver { inner_rx: rx };
        Ok(WatchTransactionStream::new(stream))
    }

    fn watch_event(&self, address: &AccountAddress, event_keys: Vec<EventKey>) {
        unimplemented!()
    }

    fn get_transaction_by_hash(&self, hash: HashValue) -> Result<SignedTransaction> {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_mock_client() {
        let rt = Runtime::new().unwrap();
        let client = MockChainClient::new(rt.executor());
        let state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state)
    }
}

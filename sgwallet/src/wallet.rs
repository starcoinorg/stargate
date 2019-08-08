use std::sync::Arc;

use chain_client::{ChainClient, RpcChainClient};
use failure::prelude::*;
use local_state_storage::LocalStateStorage;
use local_vm::LocalVM;
use nextgen_crypto::{test_utils::KeyPair};
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use star_types::{channel::SgChannelStream};
use star_types::offchain_transaction::{OffChainTransaction, SignOffChainTransaction};
use star_types::resource::Resource;
use types::account_address::AccountAddress;
use types::transaction::{SignedTransaction, TransactionOutput};
use types::vm_error::*;

pub struct Wallet<C> where C: ChainClient {
    account_address: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<C>,
    storage: Arc<LocalStateStorage<C>>,
    vm: LocalVM<LocalStateStorage<C>>,
}

impl<C> Wallet<C> where C: ChainClient {
    pub fn new(account_address: AccountAddress, keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>, rpc_host: &str, rpc_port: u32) -> Result<Wallet<RpcChainClient>> {
        let client = Arc::new(RpcChainClient::new(rpc_host, rpc_port));
        Wallet::new_with_client(account_address, keypair, client)
    }

    pub fn new_with_client(account_address: AccountAddress, keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>, client: Arc<C>) -> Result<Self> {
        let storage = Arc::new(LocalStateStorage::new(account_address, client.clone())?);
        let vm = LocalVM::new(storage.clone());
        Ok(Self {
            account_address,
            keypair,
            client,
            storage,
            vm,
        })
    }

    pub fn execute_transaction(&self, transaction: SignedTransaction) -> TransactionOutput {
        self.vm.execute_transaction(transaction)
    }

    pub fn validate_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Option<VMStatus> {
        self.vm.validate_transaction(transaction)
    }

    pub fn get_resources() -> Vec<Resource> {
        unimplemented!()
    }
}
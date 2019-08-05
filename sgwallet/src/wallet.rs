use chain_client::ChainClientFacade;
use failure::prelude::*;
use local_state_storage::LocalStateStorage;
use local_vm::LocalVM;
use nextgen_crypto::{test_utils::KeyPair};
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use star_types::{channel::SgChannelStream};
use types::account_address::AccountAddress;
use types::transaction::{SignedTransaction, TransactionOutput};
use types::vm_error::*;

use star_types::offchain_transaction::{OffChainTransaction, SignOffChainTransaction};
use star_types::resource::Resource;
use std::sync::Arc;

pub struct Wallet {
    account_address: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<ChainClientFacade>,
    storage: Arc<LocalStateStorage>,
    vm: LocalVM<LocalStateStorage>,
}

impl Wallet {
    pub fn new(keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>, rpc_host: &str, rpc_port: u32) -> Result<Self> {
        let account_address = AccountAddress::from_public_key(&keypair.public_key);
        let client = Arc::new(ChainClientFacade::new(rpc_host, rpc_port));
        let storage = Arc::new(LocalStateStorage::new(account_address.clone(), client.clone())?);
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
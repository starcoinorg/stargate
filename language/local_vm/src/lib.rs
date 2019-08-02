use config::config::{VMConfig,VMPublishingOption};
use failure::prelude::*;
use lazy_static::lazy_static;
use rental::rental;
use types::access_path::AccessPath;
use types::transaction::{SignedTransaction, TransactionOutput};
use types::vm_error::VMStatus;
use vm_runtime::{MoveVM, VMExecutor, VMVerifier};
use state_view::StateView;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig{
        publishing_options: VMPublishingOption::Open
    };
}

pub struct LocalDataStore {}

impl LocalDataStore {
    pub fn new() -> Self {
        LocalDataStore {}
    }
}

impl StateView for LocalDataStore {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        unimplemented!();
        //let (account_bob, version) = self.client.client.get_account_blob(*address)?;
        //Ok(get_account_data(account_bob, path))
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut vec = vec![];
        for path in access_paths {
            vec.push(self.get(path)?);
        }
        Ok(vec)
    }

    fn is_genesis(&self) -> bool {
        false
    }
}

struct LocalVM {
    inner: MoveVM,
    data_store: LocalDataStore,
}

impl LocalVM {
    pub fn new() -> Self {
        Self {
            inner: MoveVM::new(&VM_CONFIG),
            data_store: LocalDataStore::new(),
        }
    }

    fn validate_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Option<VMStatus> {
        // TODO: This should be implemented as an async function.
        self.inner.validate_transaction(transaction, &self.data_store)
    }

    fn execute_transaction(transaction: SignedTransaction) -> TransactionOutput {
        let data_store = LocalDataStore::new();
        MoveVM::execute_block(vec![transaction], &VM_CONFIG, &data_store).pop().unwrap()
    }
}

#[cfg(test)]
mod local_vm_test;
use config::config::{VMConfig,VMPublishingOption};
use failure::prelude::*;
use lazy_static::lazy_static;
use rental::rental;
use types::access_path::AccessPath;
use types::transaction::{SignedTransaction, TransactionOutput};
use types::vm_error::VMStatus;
use vm_runtime::{MoveVM, VMExecutor, VMVerifier};
use state_view::StateView;
use std::sync::Arc;
use atomic_refcell::AtomicRefCell;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig::offchain();
}

pub struct LocalVM{
    inner: MoveVM,
}

impl LocalVM{

    pub fn new() -> Self {
            Self {
            inner: MoveVM::new(&VM_CONFIG),
        }
    }

    pub fn validate_transaction(
        &self,
        transaction: SignedTransaction,
        state_view: &dyn StateView
    ) -> Option<VMStatus> {
        // TODO: This should be implemented as an async function.
        self.inner.validate_transaction(transaction, state_view)
    }

    pub fn execute_transaction(&self, transaction: SignedTransaction, state_view: &dyn StateView) -> TransactionOutput {
        MoveVM::execute_block(vec![transaction], &VM_CONFIG, state_view).pop().unwrap()
    }
}
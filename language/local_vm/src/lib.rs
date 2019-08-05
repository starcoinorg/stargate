use config::config::{VMConfig,VMPublishingOption};
use failure::prelude::*;
use lazy_static::lazy_static;
use rental::rental;
use types::access_path::AccessPath;
use types::transaction::{SignedTransaction, TransactionOutput};
use types::vm_error::VMStatus;
use vm_runtime::{MoveVM, VMExecutor, VMVerifier};
use state_view::StateView;
use std::borrow::Borrow;
use std::sync::Arc;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig{
        publishing_options: VMPublishingOption::Open
    };
}

pub struct LocalVM<S> where S:StateView {
    inner: MoveVM,
    state_view: Arc<S>,
}

impl <S> LocalVM<S> where S:StateView {

    pub fn new(state_view: Arc<S>) -> Self {
        Self {
            inner: MoveVM::new(&VM_CONFIG),
            state_view,
        }
    }

    pub fn validate_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Option<VMStatus> {
        // TODO: This should be implemented as an async function.
        self.inner.validate_transaction(transaction, self.state_view.as_ref())
    }

    pub fn execute_transaction(&self, transaction: SignedTransaction) -> TransactionOutput {
        MoveVM::execute_block(vec![transaction], &VM_CONFIG, self.state_view.as_ref()).pop().unwrap()
    }
}

#[cfg(test)]
mod local_vm_test;
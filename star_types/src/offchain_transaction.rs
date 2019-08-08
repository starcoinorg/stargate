use serde::{Deserialize, Serialize};

use failure::prelude::*;
use crypto::Signature;
use nextgen_crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use types::account_address::AccountAddress;
use types::transaction::{RawTransaction, SignedTransaction, TransactionStatus, TransactionOutput};
use types::contract_event::ContractEvent;
use types::write_set::WriteSet;
use types::vm_error::VMStatus;

pub trait TransactionOutputSigner {
    fn sign_txn_output(&self, txn_output: &TransactionOutput) -> Result<Ed25519Signature>;
}

#[derive(Clone, Eq, PartialEq,Debug)]
pub struct OffChainTransaction {
    /// The sender signed transaction
    txn: SignedTransaction,

    receiver: AccountAddress,

    /// transaction output
    output: TransactionOutput,

    /// sender ans receiver signature for output.
    output_signatures: Vec<Ed25519Signature>,
}

impl OffChainTransaction {
    pub fn new(txn: SignedTransaction, receiver: AccountAddress, output: TransactionOutput, output_signature: Ed25519Signature) -> Self {
        Self {
            txn,
            receiver,
            output,
            output_signatures: vec![output_signature],
        }
    }

    pub fn sign_by_receiver(&mut self, signer: impl TransactionOutputSigner) -> Result<()>{
        assert_eq!(1, self.output_signatures.len());
        let signature = signer.sign_txn_output(&self.output)?;
        self.output_signatures.push(signature);
        Ok(())
    }

    pub fn txn(&self) -> &SignedTransaction {
        &self.txn
    }

    pub fn receiver(&self) -> AccountAddress {
        self.receiver
    }

    pub fn output(&self) -> &TransactionOutput {
        &self.output
    }

    pub fn output_signatures(&self) -> &Vec<Ed25519Signature> {
        &self.output_signatures
    }
}

pub struct OffChainTransactionInput {}

pub struct OffChainTransactionOutput {}

pub struct SignOffChainTransaction {
    sign: Signature,
    data: OffChainTransaction,
}
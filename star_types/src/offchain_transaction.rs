use serde::{Deserialize, Serialize};

use failure::prelude::*;
use crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use types::account_address::AccountAddress;
use types::transaction::{RawTransaction, SignedTransaction, TransactionStatus};
use types::contract_event::ContractEvent;
use types::write_set::WriteSet;
use types::vm_error::VMStatus;
use proto_conv::{FromProto, IntoProto};
use core::convert::TryFrom;
use super::transaction_output_helper;
use protobuf::RepeatedField;
use crate::change_set::ChangeSet;


/// The output of executing a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionOutput {
    /// The list of changes this transaction intends to do.
    change_set: ChangeSet,

    /// The list of events emitted during this transaction.
    events: Vec<ContractEvent>,

    /// The amount of gas used during execution.
    gas_used: u64,

    /// The execution status.
    status: TransactionStatus,
}

impl TransactionOutput {
    pub fn new(
        change_set: ChangeSet,
        events: Vec<ContractEvent>,
        gas_used: u64,
        status: TransactionStatus,
    ) -> Self {
        TransactionOutput {
            change_set,
            events,
            gas_used,
            status,
        }
    }

    pub fn change_set(&self) -> &ChangeSet {
        &self.change_set
    }

    pub fn events(&self) -> &[ContractEvent] {
        &self.events
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub fn status(&self) -> &TransactionStatus {
        &self.status
    }
}

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

    pub fn is_travel_txn(&self) -> bool {
        for (access_path ,_) in self.output.change_set.iter(){
            if access_path.is_on_chain_resource(){
                return true;
            }
        }
        return false;
    }
}

impl FromProto for OffChainTransaction {
    type ProtoType = crate::proto::off_chain_transaction::OffChainTransaction;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {    
        let signed_tnx = SignedTransaction::from_proto(object.take_transaction()).unwrap();
        let account_address = AccountAddress::from_proto(object.get_receiver().to_vec()).unwrap();
        let transaction_output = crate::transaction_output_helper::from_pb(object.take_transaction_output())?;
        let sign_array = object.get_output_signatures();
        let mut sign_vec : Vec<Ed25519Signature> = vec![];
        for sign_bytes in sign_array.iter() {
            sign_vec.push(Ed25519Signature::try_from(sign_bytes.as_slice()).unwrap());
        }
        Ok(OffChainTransaction{
            txn:signed_tnx,
            receiver:account_address,
            output:transaction_output, 
            output_signatures:sign_vec
        })
    }
}

impl IntoProto for OffChainTransaction {
    type ProtoType = crate::proto::off_chain_transaction::OffChainTransaction;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_transaction(self.txn.into_proto());
        out.set_receiver(self.receiver.into_proto());
        out.set_transaction_output(transaction_output_helper::into_pb(self.output).unwrap());
        let mut signs:Vec<Vec<u8>> = vec![];
        for sign in self.output_signatures {
            signs.push(sign.to_bytes().to_vec());
        }
        out.set_output_signatures(RepeatedField::from_vec(signs));
        out
    }
}

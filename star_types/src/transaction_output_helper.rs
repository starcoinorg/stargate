use types::transaction::{RawTransaction, SignedTransaction, TransactionStatus, TransactionOutput};
use super::proto::transaction_output::TransactionOutput as TransactionOutputPb;

pub fn from_pb(pb: TransactionOutputPb) -> TransactionOutput {
    //TODO:change TransactionOutputPb to TransactionOutput
    unimplemented!()
}

pub fn into_pb(tx_output:TransactionOutput) -> TransactionOutputPb {
    //TODO:change TransactionOutput to TransactionOutputPb
    unimplemented!()
}
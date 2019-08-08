use types::{transaction::{RawTransaction, SignedTransaction, TransactionStatus, TransactionOutput}, write_set::WriteSet};
use super::proto::transaction_output::TransactionOutput as TransactionOutputPb;

pub fn from_pb(pb: TransactionOutputPb) -> TransactionOutput {
    //TODO:change TransactionOutputPb to TransactionOutput
//    let mut ouyput = TransactionOutput::new();
//    let mut write_set = WriteSet::from_proto(pb.get_write_set());
//    pb.get_events()
    unimplemented!()
}

pub fn into_pb(tx_output:TransactionOutput) -> TransactionOutputPb {
    //TODO:change TransactionOutput to TransactionOutputPb
    unimplemented!()
}
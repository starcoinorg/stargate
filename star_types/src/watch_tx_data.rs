use super::{transaction_output_helper};
use types::transaction::{SignedTransaction, TransactionOutput};
use proto_conv::FromProto;
use failure::prelude::*;
use core::borrow::Borrow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchTxData {
    pub signed_tx: SignedTransaction,
    pub output: TransactionOutput,
}

impl WatchTxData {
    pub fn get_signed_tx(&self) -> &SignedTransaction {
        return self.signed_tx.borrow()
    }

    pub fn get_output(&self) -> &TransactionOutput {
        return self.output.borrow()
    }
}

impl FromProto for WatchTxData {
    type ProtoType = super::proto::chain::WatchTxData;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let signed_tx = SignedTransaction::from_proto(object.take_signed_txn())?;
        let output = transaction_output_helper::from_pb(object.take_output())?;
        Ok(WatchTxData { signed_tx, output })
    }
}
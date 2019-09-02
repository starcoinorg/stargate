use super::{channel_transaction::TransactionOutput, transaction_output_helper};
use types::transaction::SignedTransaction;
use proto_conv::FromProto;
use failure::prelude::*;
use core::borrow::Borrow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchTxData {
    signed_tx: SignedTransaction,
    output: Option<TransactionOutput>,
}

impl WatchTxData {
    pub fn get_signed_tx(&self) -> &SignedTransaction {
        return self.signed_tx.borrow();
    }

    pub fn get_output(&self) -> &Option<TransactionOutput> {
        return self.output.borrow();
    }
}

impl FromProto for WatchTxData {
    type ProtoType = super::proto::chain::WatchTxData;

    fn from_proto(object: Self::ProtoType) -> Result<Self> {
        let signed_tx = SignedTransaction::from_proto(object.get_signed_txn().clone())?;

        let output = if object.has_output() {
            Some(transaction_output_helper::from_pb(object.get_output().clone())?)
        } else {
            None
        };
        Ok(WatchTxData { signed_tx, output })
    }
}
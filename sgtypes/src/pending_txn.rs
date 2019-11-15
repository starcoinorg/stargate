use crate::channel_transaction::ChannelTransaction;
use crate::channel_transaction_sigs::ChannelTransactionSigs;
use libra_crypto::HashValue;
use libra_types::transaction::TransactionOutput;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PendingTransaction {
    WaitForReceiverSig {
        request_id: HashValue,
        raw_tx: ChannelTransaction,
        output: TransactionOutput,
        sender_sigs: ChannelTransactionSigs,
    },
    WaitForApply {
        request_id: HashValue,
        raw_tx: ChannelTransaction,
        output: TransactionOutput,
        sender_sigs: ChannelTransactionSigs,
        receiver_sigs: ChannelTransactionSigs,
    },
}

impl PendingTransaction {
    pub fn request_id(&self) -> HashValue {
        match self {
            PendingTransaction::WaitForReceiverSig { request_id, .. } => request_id.clone(),
            PendingTransaction::WaitForApply { request_id, .. } => request_id.clone(),
        }
    }
}

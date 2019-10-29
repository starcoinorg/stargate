use crate::channel_transaction_info::ChannelTransactionInfo;
use crate::proof::ChannelTransactionAccumulatorProof;

/// The complete proof used to authenticate a `SignedTransaction` object.  This structure consists
/// of an `AccumulatorProof` from `LedgerInfo` to `TransactionInfo` the verifier needs to verify
/// the correctness of the `TransactionInfo` object, and the `TransactionInfo` object that is
/// supposed to match the `SignedTransaction`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedChannelTransactionProof {
    /// The accumulator proof from ledger info root to leaf that authenticates the hash of the
    /// `TransactionInfo` object.
    ledger_info_to_transaction_info_proof: ChannelTransactionAccumulatorProof,

    /// The `ChannelTransactionInfo` object at the leaf of the accumulator.
    transaction_info: ChannelTransactionInfo,
}

impl SignedChannelTransactionProof {
    /// Constructs a new `SignedTransactionProof` object using given
    /// `ledger_info_to_transaction_info_proof`.
    pub fn new(
        ledger_info_to_transaction_info_proof: ChannelTransactionAccumulatorProof,
        transaction_info: ChannelTransactionInfo,
    ) -> Self {
        Self {
            ledger_info_to_transaction_info_proof,
            transaction_info,
        }
    }

    /// Returns the `ledger_info_to_transaction_info_proof` object in this proof.
    pub fn ledger_info_to_transaction_info_proof(&self) -> &ChannelTransactionAccumulatorProof {
        &self.ledger_info_to_transaction_info_proof
    }

    /// Returns the `transaction_info` object in this proof.
    pub fn transaction_info(&self) -> &ChannelTransactionInfo {
        &self.transaction_info
    }
}

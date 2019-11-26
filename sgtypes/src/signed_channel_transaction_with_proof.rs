use crate::proof::signed_channel_transaction_proof::SignedChannelTransactionProof;
use crate::signed_channel_transaction::SignedChannelTransaction;
use failure::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::contract_event::ContractEvent;
use libra_types::ledger_info::LedgerInfo;
use libra_types::transaction::Version;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedChannelTransactionWithProof {
    pub version: Version,
    pub signed_transaction: SignedChannelTransaction,
    pub events: Option<Vec<ContractEvent>>,
    pub proof: SignedChannelTransactionProof,
}

impl SignedChannelTransactionWithProof {
    /// Verifies the signed transaction with the proof, both carried by `self`.
    ///
    /// Two things are ensured if no error is raised:
    ///   1. This signed transaction exists in the ledger represented by `ledger_info`.
    ///   2. And this signed transaction has the same `version`, `sender`, and `sequence_number` as
    /// indicated by the parameter list. If any of these parameter is unknown to the call site that
    /// is supposed to be informed via this struct, get it from the struct itself, such as:
    /// `signed_txn_with_proof.version`, `signed_txn_with_proof.signed_transaction.sender()`, etc.
    pub fn verify(
        &self,
        _ledger_info: &LedgerInfo,
        version: Version,
        proposer: AccountAddress,
        sequence_number: u64,
        channel_sequence_number: u64,
    ) -> Result<()> {
        ensure!(
            self.version == version,
            "Version ({}) is not expected ({}).",
            self.version,
            version,
        );
        ensure!(
            self.signed_transaction.raw_tx.proposer() == proposer,
            "Sender ({}) not expected ({}).",
            self.signed_transaction.raw_tx.proposer(),
            proposer,
        );
        ensure!(
            self.signed_transaction.raw_tx.sequence_number() == sequence_number,
            "Sequence number ({}) not expected ({}).",
            self.signed_transaction.raw_tx.sequence_number(),
            sequence_number,
        );
        ensure!(
            self.signed_transaction.raw_tx.channel_sequence_number() == channel_sequence_number,
            "Channel sequence number ({}) not expected ({}).",
            self.signed_transaction.raw_tx.channel_sequence_number(),
            channel_sequence_number,
        );

        // TODO(caojiafeng): impl the verification logic

        //        let events_root_hash = self.events.as_ref().map(|events| {
        //            let event_hashes: Vec<_> = events.iter().map(ContractEvent::hash).collect();
        //            get_accumulator_root_hash::<EventAccumulatorHasher>(&event_hashes)
        //        });
        //        verify_signed_transaction(
        //            ledger_info,
        //            self.signed_transaction.hash(),
        //            events_root_hash,
        //            version,
        //            &self.proof,
        //        )

        Ok(())
    }
}

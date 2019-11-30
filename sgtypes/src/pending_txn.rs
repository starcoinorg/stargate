use crate::channel_transaction::ChannelTransactionProposal;
use crate::channel_transaction_sigs::ChannelTransactionSigs;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::TransactionOutput;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Every Transaction Proposal should wait for others' signature,
/// TODO: should handle `agree or disagree`
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PendingTransaction {
    WaitForSig {
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        // TODO: or call it vote?
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    },

    WaitForApply {
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        // TODO: or call it vote?
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    },
}

impl PendingTransaction {
    pub fn add_signature(&mut self, sig: ChannelTransactionSigs) {
        match self {
            PendingTransaction::WaitForSig { signatures, .. } => {
                signatures.insert(sig.address, sig);
            }
            PendingTransaction::WaitForApply { .. } => {
                // TODO: debug_assert
            }
        }
    }
    pub fn get_signature(&self, address: &AccountAddress) -> Option<ChannelTransactionSigs> {
        match self {
            PendingTransaction::WaitForSig { signatures, .. } => signatures.get(address).cloned(),
            PendingTransaction::WaitForApply { signatures, .. } => signatures.get(address).cloned(),
        }
    }

    pub fn fulfilled(&self) -> bool {
        match self {
            PendingTransaction::WaitForApply { .. } => true,
            _ => false,
        }
    }
    pub fn try_fulfill(&mut self, participants: &BTreeSet<AccountAddress>) -> bool {
        match self {
            PendingTransaction::WaitForSig {
                signatures,
                output,
                proposal,
            } => {
                if signatures.len() == participants.len() {
                    if participants
                        .iter()
                        .all(|addr| signatures.contains_key(addr))
                    {
                        *self = PendingTransaction::WaitForApply {
                            proposal: proposal.clone(),
                            signatures: signatures.clone(),
                            output: output.clone(),
                        };
                    }
                }
            }
            PendingTransaction::WaitForApply { .. } => {
                // TODO: debug_assert
            }
        };
        self.fulfilled()
    }
}

impl
    Into<(
        ChannelTransactionProposal,
        TransactionOutput,
        BTreeMap<AccountAddress, ChannelTransactionSigs>,
    )> for PendingTransaction
{
    fn into(
        self,
    ) -> (
        ChannelTransactionProposal,
        TransactionOutput,
        BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) {
        match self {
            PendingTransaction::WaitForSig {
                proposal,
                output,
                signatures,
            } => (proposal, output, signatures),
            PendingTransaction::WaitForApply {
                proposal,
                output,
                signatures,
            } => (proposal, output, signatures),
        }
    }
}

use crate::channel_transaction::ChannelTransactionProposal;
use crate::channel_transaction_sigs::ChannelTransactionSigs;
use crate::pending_txn::ProposalLifecycle::{Agreed, Applying, Negotiating, Traveling};
use libra_types::account_address::AccountAddress;
use libra_types::transaction::TransactionOutput;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// every proposal should have these states:
/// 1. Negotiating
/// 2. Agreed
/// 3. Fulfilling
/// 4. Fulfilled
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingTransaction {
    proposal: ChannelTransactionProposal,
    output: TransactionOutput,
    // TODO: or call it vote?
    signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    lifecycle: ProposalLifecycle,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ProposalLifecycle {
    Created = 0,
    Negotiating,
    Agreed,
    Applying,
    Traveling,
    //    Fulfilling,
    //    Fulfilled,
}

impl PendingTransaction {
    pub fn new(
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Self {
        Self {
            proposal,
            output,
            signatures,
            lifecycle: Negotiating,
        }
    }
    pub fn proposal(&self) -> &ChannelTransactionProposal {
        &self.proposal
    }
    pub fn output(&self) -> &TransactionOutput {
        &self.output
    }
    pub fn signatures(&self) -> &BTreeMap<AccountAddress, ChannelTransactionSigs> {
        &self.signatures
    }
    pub fn add_signature(&mut self, sig: ChannelTransactionSigs) {
        if !self.signatures.contains_key(&sig.address) {
            self.signatures.insert(sig.address, sig);
        }
    }
    pub fn set_applying(&mut self) {
        self.lifecycle = Applying;
    }

    pub fn set_travelling(&mut self) {
        self.lifecycle = Traveling;
    }

    pub fn lifecycle(&self) -> ProposalLifecycle {
        self.lifecycle
    }

    pub fn set_lifecycle(&mut self, state: ProposalLifecycle) {
        self.lifecycle = state;
    }

    pub fn get_signature(&self, address: &AccountAddress) -> Option<ChannelTransactionSigs> {
        self.signatures.get(address).cloned()
    }

    pub fn newer_than(&self, other: &Self) -> bool {
        self.lifecycle > other.lifecycle
    }

    pub fn is_negotiating(&self) -> bool {
        self.lifecycle == Negotiating
    }
    pub fn consensus_reached(&self) -> bool {
        self.lifecycle >= Agreed
    }

    pub fn try_reach_consensus(&mut self, participants: &BTreeSet<AccountAddress>) -> bool {
        if self.lifecycle == Negotiating && self.signatures.len() == participants.len() {
            if participants
                .iter()
                .all(|addr| self.signatures.contains_key(addr))
            {
                self.lifecycle = Agreed;
            }
        }
        self.consensus_reached()
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
        let Self {
            proposal,
            output,
            signatures,
            ..
        } = self;
        (proposal, output, signatures)
    }
}

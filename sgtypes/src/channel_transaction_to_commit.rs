// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::signed_channel_transaction::SignedChannelTransaction;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::contract_event::ContractEvent;
use libra_types::vm_error::StatusCode;
use libra_types::write_set::WriteSet;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionToApply {
    pub signed_channel_txn: SignedChannelTransaction,
    pub travel: bool,
    /// tx output related
    pub write_set: WriteSet,
    // other tx output fields for later usage
    pub events: Vec<ContractEvent>,
    pub major_status: StatusCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionToCommit {
    signed_txn: SignedChannelTransaction,
    write_set: WriteSet,
    witness_states: BTreeMap<AccountAddress, AccountStateBlob>,
    events: Vec<ContractEvent>,
    major_status: StatusCode,
}

impl
    Into<(
        SignedChannelTransaction,
        WriteSet,
        BTreeMap<AccountAddress, AccountStateBlob>,
        Vec<ContractEvent>,
        StatusCode,
    )> for ChannelTransactionToCommit
{
    fn into(
        self,
    ) -> (
        SignedChannelTransaction,
        WriteSet,
        BTreeMap<AccountAddress, AccountStateBlob>,
        Vec<ContractEvent>,
        StatusCode,
    ) {
        let ChannelTransactionToCommit {
            signed_txn,
            write_set,
            witness_states,
            events,
            major_status,
        } = self;
        (signed_txn, write_set, witness_states, events, major_status)
    }
}

impl ChannelTransactionToCommit {
    pub fn new(
        signed_txn: SignedChannelTransaction,
        write_set: WriteSet,
        witness_states: BTreeMap<AccountAddress, AccountStateBlob>,
        events: Vec<ContractEvent>,
        major_status: StatusCode,
    ) -> Self {
        Self {
            signed_txn,
            write_set,
            witness_states,
            events,
            major_status,
        }
    }

    pub fn transaction(&self) -> &SignedChannelTransaction {
        &self.signed_txn
    }
    pub fn write_set(&self) -> &WriteSet {
        &self.write_set
    }
    pub fn witness_states(&self) -> &BTreeMap<AccountAddress, AccountStateBlob> {
        &self.witness_states
    }

    pub fn events(&self) -> &[ContractEvent] {
        &self.events
    }
    pub fn major_status(&self) -> StatusCode {
        self.major_status
    }
}

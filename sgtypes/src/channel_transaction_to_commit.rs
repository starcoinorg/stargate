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
    /// tx output related
    pub write_set: Option<WriteSet>,
    pub travel: bool,
    // other tx output fields for later usage
    pub events: Vec<ContractEvent>,
    pub major_status: StatusCode,
    pub gas_used: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionToCommit {
    signed_txn: SignedChannelTransaction,
    write_set: WriteSet,
    travel: bool,
    witness_states: BTreeMap<AccountAddress, AccountStateBlob>,
    events: Vec<ContractEvent>,
    major_status: StatusCode,
    gas_used: u64,
}

impl
    Into<(
        SignedChannelTransaction,
        WriteSet,
        bool,
        BTreeMap<AccountAddress, AccountStateBlob>,
        Vec<ContractEvent>,
        StatusCode,
        u64,
    )> for ChannelTransactionToCommit
{
    fn into(
        self,
    ) -> (
        SignedChannelTransaction,
        WriteSet,
        bool,
        BTreeMap<AccountAddress, AccountStateBlob>,
        Vec<ContractEvent>,
        StatusCode,
        u64,
    ) {
        let ChannelTransactionToCommit {
            signed_txn,
            write_set,
            travel,
            witness_states,
            events,
            major_status,
            gas_used,
        } = self;
        (
            signed_txn,
            write_set,
            travel,
            witness_states,
            events,
            major_status,
            gas_used,
        )
    }
}

impl ChannelTransactionToCommit {
    pub fn new(
        signed_txn: SignedChannelTransaction,
        write_set: WriteSet,
        travel: bool,
        witness_states: BTreeMap<AccountAddress, AccountStateBlob>,
        events: Vec<ContractEvent>,
        major_status: StatusCode,
        gas_used: u64,
    ) -> Self {
        Self {
            signed_txn,
            write_set,
            travel,
            witness_states,
            events,
            major_status,
            gas_used,
        }
    }

    pub fn transaction(&self) -> &SignedChannelTransaction {
        &self.signed_txn
    }
    pub fn write_set(&self) -> &WriteSet {
        &self.write_set
    }
    pub fn travel(&self) -> bool {
        self.travel
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
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }
}

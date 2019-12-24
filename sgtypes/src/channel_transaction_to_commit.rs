// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::signed_channel_transaction::SignedChannelTransaction;
use libra_types::contract_event::ContractEvent;
use libra_types::vm_error::StatusCode;
use libra_types::write_set::WriteSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionToCommit {
    pub signed_channel_txn: SignedChannelTransaction,
    /// tx output related
    pub write_set: WriteSet,
    pub travel: bool,
    // other tx output fields for later usage
    pub events: Vec<ContractEvent>,
    pub major_status: StatusCode,
    pub gas_used: u64,
}

impl ChannelTransactionToCommit {
    pub fn new(
        signed_channel_txn: SignedChannelTransaction,
        write_set: WriteSet,
        travel: bool,
        events: Vec<ContractEvent>,
        major_status: StatusCode,
        gas_used: u64,
    ) -> Self {
        Self {
            signed_channel_txn,
            write_set,
            travel,
            events,
            major_status,
            gas_used,
        }
    }

    pub fn transaction(&self) -> &SignedChannelTransaction {
        &self.signed_channel_txn
    }
    pub fn write_set(&self) -> &WriteSet {
        &self.write_set
    }
    pub fn travel(&self) -> bool {
        self.travel
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

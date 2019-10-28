// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::channel_transaction::ChannelTransaction;
use crate::channel_transaction_sigs::ChannelTransactionSigs;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::contract_event::ContractEvent;
use libra_types::vm_error::StatusCode;
use std::collections::HashMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionToCommit {
    raw_tx: ChannelTransaction,
    sender_signature: ChannelTransactionSigs,
    receiver_signature: ChannelTransactionSigs,

    /// tx output related
    account_states: HashMap<AccountAddress, AccountStateBlob>,
    events: Vec<ContractEvent>,
    gas_used: u64,
    major_status: StatusCode,
}

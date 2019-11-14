// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::ledger_info::LedgerInfo;
use libra_crypto::HashValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupInfo {
    pub ledger_info: LedgerInfo,
    pub latest_version: u64,
    pub account_state_root_hash: HashValue,
    pub ledger_frozen_subtree_hashes: Vec<HashValue>,
}

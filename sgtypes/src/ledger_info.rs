// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::hash::LedgerInfoHasher;
use crate::impl_hash;
use libra_crypto::HashValue;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LedgerInfo {
    version: u64,
    /// The root hash of transaction accumulator that includes the latest transaction.
    transaction_accumulator_hash: HashValue,

    /// Epoch number corresponds to the set of validators that are active for this ledger info.
    epoch: u64,
    timestamp_usecs: u64,
}

impl Display for LedgerInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "LedgerInfo: [version: {}, epoch: {}, timestamp (us): {}, transaction_accumulator_hash: {}]",
            self.version(),
            self.epoch(),
            self.timestamp_usecs(),
            self.transaction_accumulator_hash(),
        )
    }
}

impl LedgerInfo {
    /// Constructs a `LedgerInfo` object at a specific version using a given
    /// transaction accumulator root and consensus data hash.
    pub fn new(
        version: u64,
        transaction_accumulator_hash: HashValue,
        epoch: u64,
        timestamp_usecs: u64,
    ) -> Self {
        LedgerInfo {
            version,
            transaction_accumulator_hash,
            epoch,
            timestamp_usecs,
        }
    }

    /// Returns the version of this `LedgerInfo`.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the transaction accumulator root of this `LedgerInfo`.
    pub fn transaction_accumulator_hash(&self) -> HashValue {
        self.transaction_accumulator_hash
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn timestamp_usecs(&self) -> u64 {
        self.timestamp_usecs
    }
}

impl_hash!(LedgerInfo, LedgerInfoHasher);

// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_crypto::HashValue;

#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct HtlcPayment {
    hash_lock: HashValue,
    amount: u64,
    timeout: u64,
}

impl HtlcPayment {
    pub fn new(hash_lock: HashValue, amount: u64, timeout: u64) -> Self {
        Self {
            hash_lock,
            amount,
            timeout,
        }
    }
    pub fn hash_lock(&self) -> &HashValue {
        &self.hash_lock
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
}

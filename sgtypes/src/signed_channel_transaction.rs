// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    channel_transaction::ChannelTransaction, channel_transaction_sigs::ChannelTransactionSigs,
    hash::SignedChannelTransactionHasher, impl_hash,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedChannelTransaction {
    pub raw_tx: ChannelTransaction,
    pub sender_signature: ChannelTransactionSigs,
    pub receiver_signature: ChannelTransactionSigs,
}

impl_hash!(SignedChannelTransaction, SignedChannelTransactionHasher);
